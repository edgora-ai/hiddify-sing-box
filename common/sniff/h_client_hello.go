package sniff

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
)

const (
	// Include record headers in the bound; never allocate from an advertised length.
	maxTLSClientHelloBytes       = 64 * 1024
	maxTLSClientHelloRecordBytes = 1 << 14
)

// sniffTLSClientHelloInfo only examines records already read by the existing TLS
// parser. It does not replace TLS validation or read more data. Exactly one complete
// ClientHello is accepted, possibly fragmented across records, without trailing data.
// No name is returned on errors or ECH (including GREASE). A false encrypted result
// is conclusive only when err is nil. Callers must not relax existing TLS sniffing.
func sniffTLSClientHelloInfo(records []byte) (serverName string, encrypted bool, err error) {
	if len(records) > maxTLSClientHelloBytes {
		return "", false, errors.New("TLS ClientHello exceeds sniff limit")
	}
	handshake := make([]byte, 0, len(records))
	for len(records) > 0 {
		if len(records) < 5 {
			return "", false, io.ErrUnexpectedEOF
		}
		if records[0] != 22 {
			return "", false, errors.New("bad TLS record type")
		}
		version := binary.BigEndian.Uint16(records[1:3])
		if version < tls.VersionTLS10 || version > tls.VersionTLS12 {
			return "", false, errors.New("bad TLS record version")
		}
		recordLength := int(binary.BigEndian.Uint16(records[3:5]))
		if recordLength == 0 || recordLength > maxTLSClientHelloRecordBytes {
			return "", false, errors.New("bad TLS record length")
		}
		if recordLength > len(records)-5 {
			return "", false, io.ErrUnexpectedEOF
		}
		handshake = append(handshake, records[5:5+recordLength]...)
		records = records[5+recordLength:]
		if handshake[0] != 1 {
			return "", false, errors.New("bad TLS handshake type")
		}
		if len(handshake) < 4 {
			continue
		}
		helloLength := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
		if helloLength > maxTLSClientHelloBytes {
			return "", false, errors.New("bad TLS ClientHello length")
		}
		if len(handshake) < helloLength {
			continue
		}
		serverName, encrypted, err = sniffTLSClientHelloBody(handshake[4:helloLength])
		if err != nil {
			return "", encrypted, err
		}
		if len(handshake) != helloLength || len(records) != 0 {
			return "", encrypted, errors.New("trailing TLS ClientHello data")
		}
		return serverName, encrypted, nil
	}
	return "", false, io.ErrUnexpectedEOF
}

func sniffTLSClientHelloBody(body []byte) (serverName string, encrypted bool, err error) {
	// legacy_version, random, legacy_session_id length.
	if len(body) < 35 {
		return "", false, io.ErrUnexpectedEOF
	}
	version := binary.BigEndian.Uint16(body[:2])
	if version < tls.VersionTLS10 || version > tls.VersionTLS12 {
		return "", false, errors.New("bad TLS ClientHello version")
	}
	sessionLength := int(body[34])
	body = body[35:]
	if sessionLength > 32 {
		return "", false, errors.New("bad TLS session ID length")
	}
	if sessionLength > len(body) {
		return "", false, io.ErrUnexpectedEOF
	}
	body = body[sessionLength:]
	if len(body) < 2 {
		return "", false, io.ErrUnexpectedEOF
	}
	cipherLength := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if cipherLength < 2 || cipherLength%2 != 0 {
		return "", false, errors.New("bad TLS cipher suites length")
	}
	if cipherLength > len(body) {
		return "", false, io.ErrUnexpectedEOF
	}
	body = body[cipherLength:]
	if len(body) < 1 {
		return "", false, io.ErrUnexpectedEOF
	}
	compressionLength := int(body[0])
	body = body[1:]
	// Only the unambiguous, uncompressed form is eligible for a hostname.
	if compressionLength != 1 {
		return "", false, errors.New("bad TLS compression methods length")
	}
	if len(body) < compressionLength {
		return "", false, io.ErrUnexpectedEOF
	}
	if body[0] != 0 {
		return "", false, errors.New("bad TLS compression method")
	}
	body = body[compressionLength:]
	if len(body) < 2 {
		return "", false, io.ErrUnexpectedEOF
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if extensionsLength != len(body) {
		return "", false, errors.New("bad TLS extensions length")
	}

	// A fixed bitset bounds duplicate detection for all 16-bit extension types.
	var seenExtensions [1 << 10]uint64
	var parseError error
	for len(body) > 0 {
		if len(body) < 2 {
			return "", encrypted, errors.New("bad TLS extension header")
		}
		extensionType := binary.BigEndian.Uint16(body[:2])
		if extensionType == 0xfe0d {
			// Never attempt to distinguish real ECH from GREASE by its contents.
			encrypted = true
		}
		if len(body) < 4 {
			return "", encrypted, errors.New("bad TLS extension header")
		}
		extensionLength := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if extensionLength > len(body) {
			return "", encrypted, errors.New("bad TLS extension length")
		}
		extension := body[:extensionLength]
		body = body[extensionLength:]
		index, mask := extensionType/64, uint64(1)<<(extensionType%64)
		if seenExtensions[index]&mask != 0 && parseError == nil {
			parseError = errors.New("duplicate TLS extension")
		}
		seenExtensions[index] |= mask
		if extensionType == 0 {
			name, nameError := sniffTLSClientHelloServerName(extension)
			if nameError != nil && parseError == nil {
				parseError = nameError
			}
			serverName = name
		}
		// Other extension contents remain opaque. Continue through the whole
		// vector, even after an invalid SNI, so later ECH cannot be missed.
	}
	if parseError != nil {
		return "", encrypted, parseError
	}
	if serverName == "" {
		return "", encrypted, errors.New("missing TLS server name")
	}
	if encrypted {
		return "", true, nil
	}
	return serverName, false, nil
}

func sniffTLSClientHelloServerName(extension []byte) (string, error) {
	if len(extension) < 5 || int(binary.BigEndian.Uint16(extension[:2])) != len(extension)-2 {
		return "", errors.New("bad TLS server name list length")
	}
	if extension[2] != 0 {
		return "", errors.New("bad TLS server name type")
	}
	nameLength := int(binary.BigEndian.Uint16(extension[3:5]))
	// Exactly one host_name; additional names or bytes are ambiguous.
	if nameLength == 0 || nameLength > 253 || nameLength != len(extension)-5 {
		return "", errors.New("bad TLS server name length")
	}
	serverName := string(extension[5:])
	if _, err := netip.ParseAddr(serverName); err == nil {
		return "", errors.New("TLS server name is an IP address")
	}
	labels := strings.Split(serverName, ".")
	if len(labels) < 2 {
		return "", errors.New("TLS server name is not a FQDN")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("bad TLS server name label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return "", errors.New("bad TLS server name character")
		}
	}
	// A numeric final label is not a hostname; this also rejects non-canonical
	// dotted IP spellings that netip deliberately does not parse.
	lastLabel := labels[len(labels)-1]
	for i := 0; i < len(lastLabel); i++ {
		c := lastLabel[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return serverName, nil
		}
	}
	return "", errors.New("numeric TLS server name final label")
}
