package sniff

import (
	"bytes"
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// FallbackProxyDomain inspects only bytes already consumed by a successful sniff.
// Incomplete or encrypted ClientHellos cannot authorize a destination change.
func FallbackProxyDomain(protocol string, buffers []*buf.Buffer) string {
	const maxPayload = 64 * 1024
	var size int
	for _, buffer := range buffers {
		if buffer.Len() > maxPayload-size {
			return ""
		}
		size += buffer.Len()
	}
	if size == 0 {
		return ""
	}
	payload := make([]byte, 0, size)
	for _, buffer := range buffers {
		payload = append(payload, buffer.Bytes()...)
	}
	var domain string
	switch protocol {
	case C.ProtocolTLS:
		name, encrypted, err := sniffTLSClientHelloInfo(payload)
		if err != nil || encrypted {
			return ""
		}
		domain = name
	case C.ProtocolHTTP:
		var metadata adapter.InboundContext
		if err := HTTPHost(context.Background(), &metadata, bytes.NewReader(payload)); err != nil {
			return ""
		}
		domain = metadata.Domain
	default:
		return ""
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !M.IsDomainName(domain) || !strings.Contains(domain, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return ""
	}
	return domain
}
