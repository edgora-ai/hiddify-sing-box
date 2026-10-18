package sniff

import (
	"bytes"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

func TestFallbackProxyDomainUsesOnlyCompleteSupportedPayload(t *testing.T) {
	for _, test := range []struct {
		name, protocol, payload, expected string
	}{
		{"http-host", C.ProtocolHTTP, "GET / HTTP/1.1\r\nHost: Origin.Test:8080\r\n\r\n", "origin.test"},
		{"http-ip", C.ProtocolHTTP, "GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", ""},
		{"http-ipv6", C.ProtocolHTTP, "GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", ""},
		{"single-label", C.ProtocolHTTP, "GET / HTTP/1.1\r\nHost: printer\r\n\r\n", ""},
		{"incomplete-http", C.ProtocolHTTP, "GET / HTTP/1.1\r\nHost:", ""},
		{"invalid-http", C.ProtocolHTTP, "not a request", ""},
		{"unknown-protocol", "", "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n", ""},
		{"quic-unchanged", C.ProtocolQUIC, "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n", ""},
		{"dns-unchanged", C.ProtocolDNS, "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n", ""},
		{"malformed-tls", C.ProtocolTLS, "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(test.payload)
			original := append([]byte(nil), payload...)
			middle := len(payload) / 2
			first, second := buf.As(payload[:middle]), buf.As(payload[middle:])
			defer first.Release()
			defer second.Release()
			require.Equal(t, test.expected, FallbackProxyDomain(test.protocol, []*buf.Buffer{first, second}))
			require.Equal(t, original, payload)
		})
	}
}

func TestFallbackProxyDomainBoundsCachedPayload(t *testing.T) {
	require.Empty(t, FallbackProxyDomain(C.ProtocolTLS, nil))
	buffer := buf.As(bytes.Repeat([]byte{'a'}, 64*1024+1))
	defer buffer.Release()
	require.Empty(t, FallbackProxyDomain(C.ProtocolTLS, []*buf.Buffer{buffer}))
	empty := buf.As(nil)
	defer empty.Release()
	require.Empty(t, FallbackProxyDomain(C.ProtocolHTTP, []*buf.Buffer{empty}))
}
