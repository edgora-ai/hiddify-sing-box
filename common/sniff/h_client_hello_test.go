package sniff

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSniffTLSClientHelloInfoCryptoTLS(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			t.Parallel()
			records := tlsClientHelloTestCapture(t, version, "www.example.com")
			original := bytes.Clone(records)
			serverName, encrypted, err := sniffTLSClientHelloInfo(records)
			require.NoError(t, err)
			require.Equal(t, "www.example.com", serverName)
			require.False(t, encrypted)
			require.Equal(t, original, records)
		})
	}
	t.Run("IP omits SNI", func(t *testing.T) {
		t.Parallel()
		records := tlsClientHelloTestCapture(t, tls.VersionTLS13, "192.0.2.1")
		serverName, encrypted, err := sniffTLSClientHelloInfo(records)
		require.Error(t, err)
		require.Empty(t, serverName)
		require.False(t, encrypted)
	})
}

func TestSniffTLSClientHelloInfoVersionsAndSession(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, sessionLength := range []int{0, 32} {
			t.Run(fmt.Sprintf("%s/session_%d", tls.VersionName(version), sessionLength), func(t *testing.T) {
				t.Parallel()
				body := tlsClientHelloTestBody(tlsClientHelloTestSNI("example.com"))
				binary.BigEndian.PutUint16(body[:2], version)
				withSession := append(bytes.Clone(body[:35]), bytes.Repeat([]byte{1}, sessionLength)...)
				withSession[34] = byte(sessionLength)
				withSession = append(withSession, body[35:]...)
				records := tlsClientHelloTestRecords(tlsClientHelloTestHandshake(withSession))
				binary.BigEndian.PutUint16(records[1:3], version)
				serverName, encrypted, err := sniffTLSClientHelloInfo(records)
				require.NoError(t, err)
				require.Equal(t, "example.com", serverName)
				require.False(t, encrypted)
			})
		}
	}
}

func TestSniffTLSClientHelloInfoFragments(t *testing.T) {
	t.Parallel()
	hello := tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestSNI("example.com")))
	// Include splits inside the 24-bit handshake header and every nested vector.
	for split := 1; split < len(hello); split++ {
		records := tlsClientHelloTestRecords(hello[:split], hello[split:])
		original := bytes.Clone(records)
		serverName, encrypted, err := sniffTLSClientHelloInfo(records)
		require.NoError(t, err, "split %d", split)
		require.Equal(t, "example.com", serverName, "split %d", split)
		require.False(t, encrypted, "split %d", split)
		require.Equal(t, original, records)
	}
	records := tlsClientHelloTestFragmentRecords(hello, 1)
	serverName, encrypted, err := sniffTLSClientHelloInfo(records)
	require.NoError(t, err)
	require.Equal(t, "example.com", serverName)
	require.False(t, encrypted)

	// A partial record is never treated as a complete, unencrypted ClientHello.
	for end := 0; end < len(records); end++ {
		original := bytes.Clone(records[:end])
		serverName, _, err := sniffTLSClientHelloInfo(records[:end])
		require.Error(t, err, "record prefix %d", end)
		require.Empty(t, serverName, "record prefix %d", end)
		require.Equal(t, original, records[:end])
	}
	body := tlsClientHelloTestBody(tlsClientHelloTestSNI("example.com"))
	for end := 0; end < len(body); end++ {
		records := tlsClientHelloTestRecords(tlsClientHelloTestHandshake(body[:end]))
		serverName, _, err := sniffTLSClientHelloInfo(records)
		require.Error(t, err, "body prefix %d", end)
		require.Empty(t, serverName, "body prefix %d", end)
	}
}

func TestSniffTLSClientHelloInfoECH(t *testing.T) {
	t.Parallel()
	sni := tlsClientHelloTestSNI("public.example")
	// Synthetic outer ECH and a well-framed GREASE-style variant are both skipped.
	outer := []byte{0, 0, 1, 0, 1, 42, 0, 32}
	outer = append(outer, bytes.Repeat([]byte{0x11}, 32)...)
	outer = binary.BigEndian.AppendUint16(outer, 32)
	outer = append(outer, bytes.Repeat([]byte{0x22}, 32)...)
	ech := tlsClientHelloTestExtension(0xfe0d, outer)
	greaseOuter := bytes.Clone(outer)
	greaseOuter[5] = 0xa5
	copy(greaseOuter[8:40], bytes.Repeat([]byte{0xa5}, 32))
	grease := tlsClientHelloTestExtension(0xfe0d, greaseOuter)
	unknown := tlsClientHelloTestExtension(0x1234, []byte{1, 2, 3})
	for _, test := range []struct {
		name       string
		extensions [][]byte
		wantError  bool
	}{
		{"after SNI", [][]byte{sni, ech}, false},
		{"before SNI", [][]byte{ech, sni}, false},
		{"after other extensions", [][]byte{sni, unknown, ech}, false},
		{"GREASE after SNI", [][]byte{sni, grease}, false},
		{"empty ECH", [][]byte{sni, tlsClientHelloTestExtension(0xfe0d, nil)}, false},
		{"inner ECH", [][]byte{sni, tlsClientHelloTestExtension(0xfe0d, []byte{1})}, false},
		{"unknown ECH contents", [][]byte{sni, tlsClientHelloTestExtension(0xfe0d, []byte{0xff})}, false},
		{"no SNI", [][]byte{ech}, true},
		{"invalid SNI before ECH", [][]byte{tlsClientHelloTestSNI("192.0.2.1"), ech}, true},
		{"duplicate SNI before ECH", [][]byte{sni, sni, ech}, true},
		{"duplicate extension before ECH", [][]byte{sni, unknown, unknown, ech}, true},
		{"duplicate ECH", [][]byte{ech, sni, ech}, true},
		{"bad extension after ECH", [][]byte{sni, ech, {0}}, true},
		{"truncated ECH header", [][]byte{sni, {0xfe, 0x0d}}, true},
		{"oversized ECH length", [][]byte{sni, {0xfe, 0x0d, 0xff, 0xff}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			hello := tlsClientHelloTestHandshake(tlsClientHelloTestBody(test.extensions...))
			for _, fragmentSize := range []int{1, maxTLSClientHelloRecordBytes} {
				records := tlsClientHelloTestFragmentRecords(hello, fragmentSize)
				original := bytes.Clone(records)
				serverName, encrypted, err := sniffTLSClientHelloInfo(records)
				if test.wantError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				require.True(t, encrypted)
				require.Empty(t, serverName)
				require.Equal(t, original, records)
			}
		})
	}
}

func TestSniffTLSClientHelloInfoOpaqueExtensions(t *testing.T) {
	t.Parallel()
	sni := tlsClientHelloTestSNI("example.com")
	// Ordinary GREASE is not ECH. ECH-looking bytes inside another extension
	// are not an ECH extension either; only framed extension types count.
	body := tlsClientHelloTestBody(
		tlsClientHelloTestExtension(0x0a0a, nil),
		tlsClientHelloTestExtension(0xfafa, []byte{0xfe, 0x0d, 0, 0}),
		sni,
		tlsClientHelloTestExtension(0xffff, []byte{1}),
	)
	serverName, encrypted, err := sniffTLSClientHelloInfo(tlsClientHelloTestRecords(tlsClientHelloTestHandshake(body)))
	require.NoError(t, err)
	require.Equal(t, "example.com", serverName)
	require.False(t, encrypted)
}

func TestSniffTLSClientHelloInfoServerNames(t *testing.T) {
	t.Parallel()
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{"example.com", true},
		{"WWW.Example.COM", true},
		{"xn--fiqs8s.example", true},
		{"123.example", true},
		{"a-b.example", true},
		{strings.Repeat("a", 63) + ".example", true},
		{maxName, true},
		{"", false},
		{"singlelabel", false},
		{"192.0.2.1", false},
		{"2001:db8::1", false},
		{"[2001:db8::1]", false},
		{"::ffff:192.0.2.1", false},
		{"192.000.002.001", false},
		{"999.999.999.999", false},
		{"example.123", false},
		{".example.com", false},
		{"example.com.", false},
		{"example..com", false},
		{"-example.com", false},
		{"example-.com", false},
		{"exa_mple.com", false},
		{"*.example.com", false},
		{" example.com", false},
		{"example.com ", false},
		{"example.com:443", false},
		{"example.com/path", false},
		{"example.com\x00", false},
		{"example.com\r\n", false},
		{"例子.example", false},
		{strings.Repeat("a", 64) + ".example", false},
		{maxName + "e", false},
	} {
		t.Run(fmt.Sprintf("%q", test.name), func(t *testing.T) {
			t.Parallel()
			records := tlsClientHelloTestRecords(tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestSNI(test.name))))
			original := bytes.Clone(records)
			serverName, encrypted, err := sniffTLSClientHelloInfo(records)
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, test.name, serverName)
			} else {
				require.Error(t, err)
				require.Empty(t, serverName)
			}
			require.False(t, encrypted)
			require.Equal(t, original, records)
		})
	}
}

func TestSniffTLSClientHelloInfoMalformed(t *testing.T) {
	t.Parallel()
	sni := tlsClientHelloTestSNI("example.com")
	body := tlsClientHelloTestBody(sni)
	hello := tlsClientHelloTestHandshake(body)
	records := tlsClientHelloTestRecords(hello)
	changeBody := func(offset int, value ...byte) []byte {
		changed := bytes.Clone(body)
		copy(changed[offset:], value)
		return tlsClientHelloTestRecords(tlsClientHelloTestHandshake(changed))
	}
	changeRecord := func(offset int, value ...byte) []byte {
		changed := bytes.Clone(records)
		copy(changed[offset:], value)
		return changed
	}
	changeSNI := func(offset int, value ...byte) []byte {
		changed := bytes.Clone(sni[4:])
		copy(changed[offset:], value)
		return tlsClientHelloTestRecords(tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestExtension(0, changed))))
	}
	duplicateNames := append(bytes.Clone(sni[4:]), sni[6:]...)
	binary.BigEndian.PutUint16(duplicateNames[:2], uint16(len(duplicateNames)-2))
	multipleNameTypes := bytes.Clone(duplicateNames)
	multipleNameTypes[len(sni)-4] = 1
	duplicate := tlsClientHelloTestExtension(0x1234, nil)
	packet := func(extensions ...[]byte) []byte {
		return tlsClientHelloTestRecords(tlsClientHelloTestHandshake(tlsClientHelloTestBody(extensions...)))
	}
	for _, test := range []struct {
		name    string
		records []byte
	}{
		{"empty", nil},
		{"record header", records[:4]},
		{"record payload", records[:len(records)-1]},
		{"record type", changeRecord(0, 23)},
		{"record version unknown", changeRecord(1, 4, 0)},
		{"record SSL3", changeRecord(1, 3, 0)},
		{"record TLS13 version", changeRecord(1, 3, 4)},
		{"zero record length", changeRecord(3, 0, 0)},
		{"short record length", changeRecord(3, 0, byte(len(hello)-1))},
		{"long record length", changeRecord(3, 0, byte(len(hello)+1))},
		{"max record length", changeRecord(3, 0xff, 0xff)},
		{"handshake type", changeRecord(5, 2)},
		{"zero handshake length", changeRecord(6, 0, 0, 0)},
		{"short handshake length", changeRecord(6, 0, 0, byte(len(body)-1))},
		{"long handshake length", changeRecord(6, 0, 0, byte(len(body)+1))},
		{"max handshake length", changeRecord(6, 0xff, 0xff, 0xff)},
		{"over limit handshake length", changeRecord(6, 1, 0, 0)},
		{"ClientHello SSL3", changeBody(0, 3, 0)},
		{"ClientHello future version", changeBody(0, 3, 4)},
		{"long session ID", changeBody(34, 33)},
		{"empty cipher suites", changeBody(35, 0, 0)},
		{"odd cipher suites", changeBody(35, 0, 3)},
		{"oversized cipher suites", changeBody(35, 0xff, 0xfe)},
		{"empty compression", changeBody(39, 0)},
		{"multiple compression methods", changeBody(39, 2)},
		{"oversized compression", changeBody(39, 255)},
		{"non-null compression", changeBody(40, 1)},
		{"short extensions vector", changeBody(41, 0, byte(len(sni)-1))},
		{"long extensions vector", changeBody(41, 0, byte(len(sni)+1))},
		{"max extensions vector", changeBody(41, 0xff, 0xff)},
		{"short extension", changeBody(45, 0, byte(len(sni)-5))},
		{"long extension", changeBody(45, 0xff, 0xff)},
		{"no extensions", packet()},
		{"no SNI", packet(tlsClientHelloTestExtension(0x0a0a, nil))},
		{"empty SNI", packet(tlsClientHelloTestExtension(0, nil))},
		{"empty SNI list", packet(tlsClientHelloTestExtension(0, []byte{0, 0}))},
		{"short SNI list", changeSNI(0, 0, 1)},
		{"long SNI list", changeSNI(0, 0xff, 0xff)},
		{"unknown name type", changeSNI(2, 1)},
		{"empty host name", changeSNI(3, 0, 0)},
		{"short host name", changeSNI(3, 0, 1)},
		{"long host name", changeSNI(3, 0xff, 0xff)},
		{"duplicate names", packet(tlsClientHelloTestExtension(0, duplicateNames))},
		{"multiple name types", packet(tlsClientHelloTestExtension(0, multipleNameTypes))},
		{"duplicate SNI", packet(sni, sni)},
		{"conflicting SNI", packet(sni, tlsClientHelloTestSNI("other.example"))},
		{"duplicate other extension", packet(sni, duplicate, duplicate)},
		{"duplicate GREASE extension", packet(sni, tlsClientHelloTestExtension(0xfafa, nil), tlsClientHelloTestExtension(0xfafa, nil))},
		{"trailing extension byte", packet(sni, []byte{0})},
		{"trailing extension header", packet(sni, []byte{0x12, 0x34, 0})},
		{"trailing body byte", tlsClientHelloTestRecords(tlsClientHelloTestHandshake(append(bytes.Clone(body), 0)))},
		{"trailing handshake byte", tlsClientHelloTestRecords(append(bytes.Clone(hello), 0))},
		{"two handshakes", tlsClientHelloTestRecords(append(bytes.Clone(hello), hello...))},
		{"two ClientHello records", append(bytes.Clone(records), records...)},
		{"trailing record byte", append(bytes.Clone(records), 0)},
		{"trailing application record", append(bytes.Clone(records), 23, 3, 3, 0, 1, 0)},
		{"interrupted handshake", append(tlsClientHelloTestRecords(hello[:2]), 20, 3, 3, 0, 1, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			original := bytes.Clone(test.records)
			serverName, encrypted, err := sniffTLSClientHelloInfo(test.records)
			require.Error(t, err)
			require.Empty(t, serverName)
			require.False(t, encrypted)
			require.Equal(t, original, test.records)
		})
	}
}

func TestSniffTLSClientHelloInfoECHWithTrailingData(t *testing.T) {
	t.Parallel()
	hello := tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestSNI("public.example"), tlsClientHelloTestExtension(0xfe0d, nil)))
	for _, records := range [][]byte{
		tlsClientHelloTestRecords(append(bytes.Clone(hello), 0)),
		append(tlsClientHelloTestRecords(hello), 23, 3, 3, 0, 1, 0),
	} {
		serverName, encrypted, err := sniffTLSClientHelloInfo(records)
		require.Error(t, err)
		require.True(t, encrypted)
		require.Empty(t, serverName)
	}
}

func TestSniffTLSClientHelloInfoCapacity(t *testing.T) {
	t.Parallel()
	sni := tlsClientHelloTestSNI("example.com")
	baseLength := len(tlsClientHelloTestHandshake(tlsClientHelloTestBody(sni)))
	for _, delta := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("total_limit_%+d", delta), func(t *testing.T) {
			t.Parallel()
			// Four records contribute 20 header bytes at the 64 KiB boundary.
			paddingLength := maxTLSClientHelloBytes + delta - 20 - baseLength - 4
			hello := tlsClientHelloTestHandshake(tlsClientHelloTestBody(sni, tlsClientHelloTestExtension(21, make([]byte, paddingLength))))
			records := tlsClientHelloTestFragmentRecords(hello, maxTLSClientHelloRecordBytes)
			require.Len(t, records, maxTLSClientHelloBytes+delta)
			original := bytes.Clone(records)
			serverName, encrypted, err := sniffTLSClientHelloInfo(records)
			if delta > 0 {
				require.Error(t, err)
				require.Empty(t, serverName)
			} else {
				require.NoError(t, err)
				require.Equal(t, "example.com", serverName)
			}
			require.False(t, encrypted)
			require.Equal(t, original, records)
		})
	}
	for _, delta := range []int{0, 1} {
		t.Run(fmt.Sprintf("record_limit_%+d", delta), func(t *testing.T) {
			t.Parallel()
			paddingLength := maxTLSClientHelloRecordBytes + delta - baseLength - 4
			hello := tlsClientHelloTestHandshake(tlsClientHelloTestBody(sni, tlsClientHelloTestExtension(21, make([]byte, paddingLength))))
			require.Len(t, hello, maxTLSClientHelloRecordBytes+delta)
			serverName, encrypted, err := sniffTLSClientHelloInfo(tlsClientHelloTestRecords(hello))
			if delta > 0 {
				require.Error(t, err)
				require.Empty(t, serverName)
			} else {
				require.NoError(t, err)
				require.Equal(t, "example.com", serverName)
			}
			require.False(t, encrypted)
		})
	}
}

func FuzzSniffTLSClientHelloInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add(tlsClientHelloTestRecords(tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestSNI("example.com")))))
	f.Add(tlsClientHelloTestFragmentRecords(tlsClientHelloTestHandshake(tlsClientHelloTestBody(tlsClientHelloTestSNI("public.example"), tlsClientHelloTestExtension(0xfe0d, nil))), 1))
	f.Add(make([]byte, maxTLSClientHelloBytes+1))
	f.Fuzz(func(t *testing.T, records []byte) {
		original := bytes.Clone(records)
		serverName, encrypted, err := sniffTLSClientHelloInfo(records)
		require.Equal(t, original, records)
		if err != nil || encrypted {
			require.Empty(t, serverName)
		} else {
			require.NotEmpty(t, serverName)
			require.LessOrEqual(t, len(serverName), 253)
		}
	})
}

func tlsClientHelloTestCapture(t *testing.T, version uint16, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(client, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
			MaxVersion: version,
		}).HandshakeContext(ctx)
	}()
	var records, handshake []byte
	for {
		var header [5]byte
		_, err := io.ReadFull(server, header[:])
		require.NoError(t, err)
		require.Equal(t, byte(22), header[0])
		payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
		_, err = io.ReadFull(server, payload)
		require.NoError(t, err)
		records = append(records, header[:]...)
		records = append(records, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) >= 4 {
			helloLength := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if len(handshake) >= helloLength {
				break
			}
		}
	}
	require.NoError(t, server.Close())
	select {
	case err := <-done:
		// Only capture ClientHello; no server handshake or certificate is needed.
		require.Error(t, err)
	case <-ctx.Done():
		t.Fatal("TLS client did not stop after closing the in-memory pipe")
	}
	return records
}

func tlsClientHelloTestBody(extensions ...[]byte) []byte {
	// A fixed TLS 1.2 ClientHello: empty session ID, one cipher, null compression.
	body := make([]byte, 35)
	binary.BigEndian.PutUint16(body[:2], tls.VersionTLS12)
	body = append(body, 0, 2, 0, 0x2f, 1, 0)
	vector := bytes.Join(extensions, nil)
	body = binary.BigEndian.AppendUint16(body, uint16(len(vector)))
	return append(body, vector...)
}

func tlsClientHelloTestSNI(serverName string) []byte {
	name := []byte{0}
	name = binary.BigEndian.AppendUint16(name, uint16(len(serverName)))
	name = append(name, serverName...)
	vector := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
	vector = append(vector, name...)
	return tlsClientHelloTestExtension(0, vector)
}

func tlsClientHelloTestExtension(extensionType uint16, data []byte) []byte {
	extension := binary.BigEndian.AppendUint16(nil, extensionType)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(data)))
	return append(extension, data...)
}

func tlsClientHelloTestHandshake(body []byte) []byte {
	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

func tlsClientHelloTestRecords(fragments ...[]byte) []byte {
	var records []byte
	for _, fragment := range fragments {
		records = append(records, 22, 3, 1)
		records = binary.BigEndian.AppendUint16(records, uint16(len(fragment)))
		records = append(records, fragment...)
	}
	return records
}

func tlsClientHelloTestFragmentRecords(hello []byte, fragmentSize int) []byte {
	var fragments [][]byte
	for len(hello) > 0 {
		length := min(len(hello), fragmentSize)
		fragments = append(fragments, hello[:length])
		hello = hello[length:]
	}
	return tlsClientHelloTestRecords(fragments...)
}
