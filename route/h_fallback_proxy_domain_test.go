package route

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	SBufio "github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	hFallbackDomain  = "origin.fallback.example.test"
	hFallbackInbound = "fallback-test-tun"
	hFallbackTimeout = 5 * time.Second
)

var (
	// TEST-NET addresses stand for a cold, non-FakeIP destination and client.
	// They are metadata only: the fixture never dials them or public DNS.
	hFallbackIP     = netip.MustParseAddr("203.0.113.19")
	hFallbackClient = netip.MustParseAddr("192.0.2.20")
)

func hFallbackRule(action option.RuleAction, conditions option.RawDefaultRule) option.Rule {
	return option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: conditions,
		RuleAction:     action,
	}}
}

func hFallbackSniffRule(enabled bool) option.Rule {
	return hFallbackRule(option.RuleAction{
		Action: C.RuleActionTypeSniff,
		SniffOptions: option.RouteActionSniff{
			Sniffer:                        badoption.Listable[string]{C.ProtocolTLS},
			Timeout:                        badoption.Duration(time.Second),
			PreserveDomainForFallbackProxy: enabled,
		},
	}, option.RawDefaultRule{})
}

func hFallbackNewRule(t *testing.T, options option.Rule) adapter.Rule {
	t.Helper()
	rule, err := R.NewRule(context.Background(), log.NewNOPFactory().NewLogger("test"), options, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, rule.Close()) })
	return rule
}

func hFallbackDNSAnswer(domain string, address netip.Addr, ttl uint32) *dns.Msg {
	queryType := uint16(dns.TypeAAAA)
	if address.Is4() {
		queryType = dns.TypeA
	}
	question := new(dns.Msg).SetQuestion(dns.Fqdn(domain), queryType)
	response := new(dns.Msg).SetReply(question)
	header := dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: queryType, Class: dns.ClassINET, Ttl: ttl}
	if address.Is4() {
		response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IP(address.AsSlice())}}
	} else {
		response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())}}
	}
	return response
}

func TestH_FallbackProxyDomainSniffRuleJSON(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		want      bool
	}{
		{"default_off", `{"action":"sniff","sniffer":"tls"}`, false},
		{"explicit_off", `{"action":"sniff","sniffer":"tls","preserve_domain_for_fallback_proxy":false}`, false},
		{"explicit_on", `{"action":"sniff","sniffer":"tls","preserve_domain_for_fallback_proxy":true}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options option.Rule
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(test.raw), &options))
			require.Equal(t, test.want, options.DefaultOptions.SniffOptions.PreserveDomainForFallbackProxy)
			rule := hFallbackNewRule(t, options)
			action, ok := rule.Action().(*R.RuleActionSniff)
			require.True(t, ok)
			require.Equal(t, test.want, action.PreserveDomainForFallbackProxy, "R.NewRule must copy the JSON option")
			require.Len(t, action.StreamSniffers, 1)
			options.DefaultOptions.SniffOptions.PreserveDomainForFallbackProxy = !test.want
			require.Equal(t, test.want, action.PreserveDomainForFallbackProxy, "the action must not alias mutable options")

			router := &Router{}
			router.resetSniffDNSAssociations([]adapter.Rule{rule})
			if test.want {
				require.NotNil(t, router.sniffDNS.Load())
			} else {
				require.Nil(t, router.sniffDNS.Load())
			}
		})
	}
}

func TestH_FallbackProxyDomainAssociationLifecycle(t *testing.T) {
	on := hFallbackNewRule(t, hFallbackSniffRule(true))
	off := hFallbackNewRule(t, hFallbackSniffRule(false))
	router := &Router{ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("test")}
	router.resetSniffDNSAssociations([]adapter.Rule{off, on})
	previous := router.sniffDNS.Load()
	require.NotNil(t, previous)
	previous.record(hFallbackInbound, hFallbackClient, hFallbackDNSAnswer(hFallbackDomain, hFallbackIP, 30))
	require.True(t, previous.matches(hFallbackInbound, hFallbackClient, hFallbackDomain, hFallbackIP))

	router.resetSniffDNSAssociations([]adapter.Rule{on})
	current := router.sniffDNS.Load()
	require.NotNil(t, current)
	require.NotSame(t, previous, current, "reload must replace, not reuse, the authorization table")
	previous.record(hFallbackInbound, hFallbackClient, hFallbackDNSAnswer(hFallbackDomain, hFallbackIP, 30))
	require.False(t, current.matches(hFallbackInbound, hFallbackClient, hFallbackDomain, hFallbackIP), "an old in-flight delivery must not authorize the new lifecycle")
	current.record(hFallbackInbound, hFallbackClient, hFallbackDNSAnswer(hFallbackDomain, hFallbackIP, 30))
	require.True(t, current.matches(hFallbackInbound, hFallbackClient, hFallbackDomain, hFallbackIP))
	router.resetSniffDNSAssociations([]adapter.Rule{off})
	require.Nil(t, router.sniffDNS.Load())
	router.resetSniffDNSAssociations([]adapter.Rule{on})
	require.NoError(t, router.Close())
	require.Nil(t, router.sniffDNS.Load(), "closing the router must drop DNS authorization")
}

// The leaf is deliberately a recording TCP dialer, not a VMess implementation.
// BOTH IP and FQDN destinations reach the SAME trusted local origin. In particular,
// the off/negative cases still obtain HTTPS successfully; these tests exercise the
// transformation and byte transparency, not a fabricated remote SSL failure.
type hFallbackRecordingDialer struct {
	origin       string
	outboundType string
	trace        *hFallbackTrace
}

func (d *hFallbackRecordingDialer) Type() string           { return d.outboundType }
func (d *hFallbackRecordingDialer) Tag() string            { return "fallback-leaf" }
func (d *hFallbackRecordingDialer) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (d *hFallbackRecordingDialer) Dependencies() []string { return nil }
func (d *hFallbackRecordingDialer) IsReady() bool          { return d.origin != "" }
func (d *hFallbackRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, fmt.Errorf("isolated TLS fixture does not dial %s", network)
	}
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		return nil, errors.New("real ConnectionManager did not attach inbound metadata")
	}
	d.trace.add("dial", *metadata, destination)
	return (&net.Dialer{Timeout: hFallbackTimeout}).DialContext(ctx, N.NetworkTCP, d.origin)
}
func (d *hFallbackRecordingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("isolated TCP fixture does not implement UDP dialing")
}

type hFallbackOutboundManager struct {
	adapter.OutboundManager
	selected adapter.Outbound
	byTag    map[string]adapter.Outbound
}

func (m *hFallbackOutboundManager) Default() adapter.Outbound { return m.selected }
func (m *hFallbackOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

type hFallbackDNSRouter struct {
	adapter.DNSRouter
	reverseDomain string
	reverseCalls  int
	lookupCalls   int
}

func (d *hFallbackDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	d.reverseCalls++
	return d.reverseDomain, d.reverseDomain != ""
}
func (d *hFallbackDNSRouter) Lookup(_ context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.lookupCalls++
	if domain != hFallbackDomain {
		return nil, fmt.Errorf("unexpected isolated DNS lookup: %s", domain)
	}
	return []netip.Addr{hFallbackIP}, nil
}

type hFallbackDNSTransports struct{ adapter.DNSTransportManager }

func (*hFallbackDNSTransports) FakeIP() adapter.FakeIPTransport { return nil }

type hFallbackTraceEvent struct {
	stage       string
	metadata    adapter.InboundContext
	destination M.Socksaddr
}

type hFallbackTrace struct {
	mu     sync.Mutex
	events []hFallbackTraceEvent
}

func (s *hFallbackTrace) add(stage string, metadata adapter.InboundContext, destination M.Socksaddr) {
	metadata.DestinationAddresses = slices.Clone(metadata.DestinationAddresses)
	metadata.OutboundChain = slices.Clone(metadata.OutboundChain)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, hFallbackTraceEvent{stage, metadata, destination})
}
func (s *hFallbackTrace) snapshot() []hFallbackTraceEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

type hFallbackObservedManager struct {
	*ConnectionManager
	trace *hFallbackTrace
}

func (m *hFallbackObservedManager) NewConnection(ctx context.Context, dialer N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	m.trace.add("connection-manager", metadata, metadata.Destination)
	m.ConnectionManager.NewConnection(ctx, dialer, conn, metadata, onClose)
}

type hFallbackHandler struct {
	*hFallbackRecordingDialer
	manager *hFallbackObservedManager
}

func (h *hFallbackHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.trace.add("handler", metadata, metadata.Destination)
	h.manager.NewConnection(ctx, h.hFallbackRecordingDialer, conn, metadata, onClose)
}

// A per-connection group is intentionally also tagged as VMess in one case:
// recognizing a proxy-looking Type must not authorize unwrapping this group.
type hFallbackPerConnectionGroup struct {
	*hFallbackRecordingDialer
	selectedCalls int
}

func (*hFallbackPerConnectionGroup) SelectsPerConnection() {}
func (g *hFallbackPerConnectionGroup) All() []string       { return []string{g.Tag()} }
func (g *hFallbackPerConnectionGroup) Selected(string) adapter.Outbound {
	g.selectedCalls++
	return g.hFallbackRecordingDialer
}
func (*hFallbackPerConnectionGroup) AttachConnection(io.Closer) func() { return func() {} }

type hFallbackTracker struct {
	trace    *hFallbackTrace
	input    *hFallbackBytes
	consumed []byte
	matched  adapter.Rule
}

func (s *hFallbackTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, matched adapter.Rule, _ adapter.Outbound) net.Conn {
	s.trace.add("tracker", metadata, metadata.Destination)
	s.matched = matched
	if s.input != nil {
		s.consumed = s.input.snapshot()
	}
	return conn
}
func (s *hFallbackTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, matched adapter.Rule, _ adapter.Outbound) N.PacketConn {
	s.trace.add("packet-tracker", metadata, metadata.Destination)
	s.matched = matched
	return conn
}
func (*hFallbackTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type hFallbackBytes struct {
	mu   sync.Mutex
	data []byte
}

func (b *hFallbackBytes) append(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, data...)
}
func (b *hFallbackBytes) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data)
}

type hFallbackWireConn struct {
	net.Conn
	reads, writes *hFallbackBytes
}

func (c *hFallbackWireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.reads != nil {
		c.reads.append(p[:n])
	}
	return n, err
}
func (c *hFallbackWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.writes != nil {
		c.writes.append(p[:n])
	}
	return n, err
}

func hFallbackClose(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("close isolated fixture: %v", err)
	}
}

func hFallbackReceive[T any](t *testing.T, channel <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(hFallbackTimeout):
		t.Fatalf("timed out joining %s", name)
		var zero T
		return zero
	}
}

func hFallbackTrust(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated fallback regression CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hFallbackDomain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{hFallbackDomain}, IPAddresses: []net.IP{net.IP(hFallbackIP.AsSlice())},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, caCertificate, public, caPrivate)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}, roots
}

type hFallbackOriginResult struct {
	serverName, host string
	body, wire       []byte
	err              error
}

func hFallbackServeOrigin(ctx context.Context, listener net.Listener, certificate tls.Certificate, responseBody string) (result hFallbackOriginResult) {
	conn, err := listener.Accept()
	if err != nil {
		result.err = fmt.Errorf("accept isolated origin: %w", err)
		return
	}
	defer func() { result.err = errors.Join(result.err, conn.Close()) }()
	deadline, ok := ctx.Deadline()
	if !ok {
		result.err = errors.New("origin requires a test deadline")
		return
	}
	if err = conn.SetDeadline(deadline); err != nil {
		result.err = fmt.Errorf("origin deadline: %w", err)
		return
	}
	wire := &hFallbackBytes{}
	defer func() { result.wire = wire.snapshot() }()
	tlsConn := tls.Server(&hFallbackWireConn{Conn: conn, reads: wire}, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
	})
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		result.err = fmt.Errorf("origin TLS handshake: %w", err)
		return
	}
	result.serverName = tlsConn.ConnectionState().ServerName
	request, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		result.err = fmt.Errorf("origin HTTP request: %w", err)
		return
	}
	result.host = request.Host
	result.body, err = io.ReadAll(request.Body)
	result.err = errors.Join(err, request.Body.Close())
	if result.err != nil {
		return
	}
	_, result.err = fmt.Fprintf(tlsConn, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(responseBody), responseBody)
	return
}

type hFallbackTLSConfig struct {
	disable, unmatchedSniff, failSniff, noSNI bool
	selector, handler, perConnection          bool
	leafType, association, reverseDomain      string
	metadata                                  func(*adapter.InboundContext)
	terminal                                  *option.RawDefaultRule
	overrideAddress                           string
	overrideSamePort, resolve                 bool
}

func hFallbackRunTLS(t *testing.T, certificate tls.Certificate, roots *x509.CertPool, config hFallbackTLSConfig, wantRewrite bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hFallbackTimeout)
	t.Cleanup(cancel)
	listener, err := net.ListenTCP(N.NetworkTCP, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	require.NoError(t, listener.SetDeadline(time.Now().Add(hFallbackTimeout)))
	t.Cleanup(func() { hFallbackClose(t, listener) })
	responseBody := "trusted isolated origin: " + t.Name()
	originResult := make(chan hFallbackOriginResult, 1)
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		originResult <- hFallbackServeOrigin(ctx, listener, certificate, responseBody)
	}()
	t.Cleanup(func() {
		hFallbackClose(t, listener)
		hFallbackReceive(t, originDone, "origin goroutine")
	})

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	metadata := adapter.InboundContext{
		Inbound: hFallbackInbound, InboundType: C.TypeTun, Network: N.NetworkTCP, IPVersion: 4,
		Source: M.Socksaddr{Addr: hFallbackClient, Port: port}, Destination: M.Socksaddr{Addr: hFallbackIP, Port: port},
	}
	if config.metadata != nil {
		config.metadata(&metadata)
	}
	// The real routeConnection input is cold: DNS association seeding below does
	// not populate metadata.Domain, a reverse cache, FakeIP, or sniff provenance.
	if config.reverseDomain != "" {
		require.Empty(t, metadata.Domain)
	}
	initial := metadata
	inputBytes, uploadBytes := &hFallbackBytes{}, &hFallbackBytes{}
	clientPipe, routerPipe := net.Pipe()
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, clientPipe.SetDeadline(deadline))
	require.NoError(t, routerPipe.SetDeadline(deadline))
	t.Cleanup(func() { hFallbackClose(t, clientPipe); hFallbackClose(t, routerPipe) })
	input := &hFallbackWireConn{Conn: routerPipe, reads: inputBytes}
	client := &hFallbackWireConn{Conn: clientPipe, writes: uploadBytes}

	trace := &hFallbackTrace{}
	manager := &hFallbackObservedManager{ConnectionManager: NewConnectionManager(log.NewNOPFactory().NewLogger("connection")), trace: trace}
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	leafType := config.leafType
	if leafType == "" {
		leafType = C.TypeVMess
	}
	dialer := &hFallbackRecordingDialer{origin: listener.Addr().String(), outboundType: leafType, trace: trace}
	var leaf adapter.Outbound = dialer
	if config.handler {
		leaf = &hFallbackHandler{hFallbackRecordingDialer: dialer, manager: manager}
	}
	var perConnection *hFallbackPerConnectionGroup
	if config.perConnection {
		perConnection = &hFallbackPerConnectionGroup{hFallbackRecordingDialer: dialer}
		leaf = perConnection
	}
	outbounds := &hFallbackOutboundManager{selected: leaf, byTag: map[string]adapter.Outbound{leaf.Tag(): leaf}}
	if config.selector {
		selectorContext := service.ContextWith[adapter.OutboundManager](ctx, outbounds)
		selected, createErr := group.NewSelector(selectorContext, nil, log.NewNOPFactory().NewLogger("selector"), "fallback-selector", option.SelectorOutboundOptions{
			Outbounds: []string{leaf.Tag()}, Default: leaf.Tag(),
		})
		require.NoError(t, createErr)
		require.NoError(t, selected.(*group.Selector).Start())
		outbounds.selected = selected
		outbounds.byTag[selected.Tag()] = selected
	}
	dnsRouter := &hFallbackDNSRouter{reverseDomain: config.reverseDomain}
	tracker := &hFallbackTracker{trace: trace, input: inputBytes}
	router := &Router{
		ctx: ctx, logger: log.NewNOPFactory().NewLogger("router"), outbound: outbounds,
		dns: dnsRouter, dnsTransport: &hFallbackDNSTransports{}, connection: manager,
		trackers: []adapter.ConnectionTracker{tracker},
		// processSearcher and neighborResolver intentionally remain nil.
	}
	sniffRule := hFallbackSniffRule(!config.disable)
	if config.unmatchedSniff {
		sniffRule.DefaultOptions.Inbound = badoption.Listable[string]{"another-tun"}
	}
	if config.failSniff {
		sniffRule.DefaultOptions.SniffOptions.Sniffer = badoption.Listable[string]{C.ProtocolHTTP}
	}
	rules := []option.Rule{sniffRule}
	if config.disable {
		// Keep DNS recording enabled by a different, nonmatching rule, so the
		// flag-off control cannot pass merely because its DNS table is nil.
		unmatched := hFallbackSniffRule(true)
		unmatched.DefaultOptions.Network = badoption.Listable[string]{N.NetworkUDP}
		rules = append(rules, unmatched)
	}
	want := initial
	if config.overrideAddress != "" || config.overrideSamePort {
		override := option.RouteOptionsActionOptions{OverrideAddress: config.overrideAddress}
		if config.overrideSamePort {
			override.OverridePort = initial.Destination.Port
		}
		rules = append(rules, hFallbackRule(option.RuleAction{Action: C.RuleActionTypeRouteOptions, RouteOptionsOptions: override}, option.RawDefaultRule{}))
		if !want.RouteOriginalDestination.IsValid() {
			want.RouteOriginalDestination = want.Destination
		}
		if config.overrideAddress != "" {
			address := M.ParseSocksaddrHostPort(config.overrideAddress, initial.Destination.Port)
			want.Destination = address
			want.DestinationAddresses = nil
		}
	}
	if config.resolve {
		rules = append(rules, hFallbackRule(option.RuleAction{Action: C.RuleActionTypeResolve}, option.RawDefaultRule{}))
		want.DestinationAddresses = []netip.Addr{hFallbackIP}
	}
	if config.terminal != nil {
		rules = append(rules, hFallbackRule(option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: leaf.Tag()}}, *config.terminal))
	}
	require.NoError(t, router.Initialize(rules, nil))
	t.Cleanup(func() { require.NoError(t, router.Close()) })
	require.NotNil(t, router.sniffDNS.Load())
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	associations := newSniffDNSAssociations(16, time.Minute, func() time.Time { return now })
	router.sniffDNS.Store(associations)
	seedInbound, seedClient, seedDomain, seedIP := metadata.Inbound, metadata.Source.Addr, hFallbackDomain, metadata.Destination.Addr
	if !seedIP.IsValid() {
		seedIP = hFallbackIP
	}
	switch config.association {
	case "wrong_inbound":
		seedInbound = "another-tun"
	case "wrong_client":
		seedClient = netip.MustParseAddr("192.0.2.21")
	case "wrong_ip":
		seedIP = netip.MustParseAddr("203.0.113.99")
	case "wrong_name":
		seedDomain = "another.example.test"
	}
	// This explicitly seeds the forward association helper. Successful wire DNS
	// delivery/observer behavior is tested separately, not claimed by this fixture.
	if config.association != "missing" {
		associations.record(seedInbound, seedClient, hFallbackDNSAnswer(seedDomain, seedIP, 30))
		require.True(t, associations.matches(seedInbound, seedClient, seedDomain, seedIP), "verify actual seeded state and readback")
	}
	if config.association == "expired" {
		now = now.Add(30 * time.Second)
	}
	if config.association != "" {
		require.False(t, associations.matches(metadata.Inbound, metadata.Source.Addr, hFallbackDomain, metadata.Destination.Addr))
	}
	if wantRewrite {
		require.Empty(t, initial.Domain, "positive route input must not depend on a warm reverse mapping")
		require.False(t, initial.FakeIP)
		require.Empty(t, initial.SniffedDomainForFallbackProxy)
		require.False(t, initial.SniffedDestination.IsValid())
		want.RouteOriginalDestination = initial.Destination
		want.Destination = M.Socksaddr{Fqdn: hFallbackDomain, Port: initial.Destination.Port}
		want.DestinationAddresses = nil
	}

	routed := make(chan error, 1)
	routeDone := make(chan struct{})
	closed := make(chan error, 1)
	copyDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		routed <- router.routeConnection(ctx, input, metadata, N.OnceClose(func(err error) {
			defer close(copyDone)
			closed <- err
		}))
	}()
	t.Cleanup(func() {
		hFallbackClose(t, clientPipe)
		hFallbackClose(t, routerPipe)
		hFallbackReceive(t, routeDone, "routeConnection goroutine")
		for _, event := range trace.snapshot() {
			if event.stage == "connection-manager" {
				hFallbackReceive(t, copyDone, "ConnectionManager copy lifecycle")
				break
			}
		}
	})
	serverName := hFallbackDomain
	if config.noSNI {
		serverName = hFallbackIP.String() // Valid IP SAN; crypto/tls emits no SNI.
	}
	tlsClient := tls.Client(client, &tls.Config{
		RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	require.NoError(t, tlsClient.HandshakeContext(ctx), "IP and FQDN paths must both reach a trusted origin")
	require.NotEmpty(t, tlsClient.ConnectionState().VerifiedChains, "certificate verification must be real, not bypassed")
	requestBody := bytes.Repeat([]byte("fallback-payload:\x00\xff\n"), 1024)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+hFallbackDomain+"/cached-first-packet", bytes.NewReader(requestBody))
	require.NoError(t, err)
	request.Close = true
	require.NoError(t, request.Write(tlsClient))
	response, err := http.ReadResponse(bufio.NewReader(tlsClient), request)
	require.NoError(t, err)
	body, readErr := io.ReadAll(response.Body)
	require.NoError(t, errors.Join(readErr, response.Body.Close()))
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, responseBody, string(body))
	hFallbackClose(t, clientPipe) // Do not add a post-request TLS close_notify to the upload comparison.
	origin := hFallbackReceive(t, originResult, "origin result")
	require.NoError(t, origin.err)
	require.Equal(t, requestBody, origin.body, "HTTP payload must arrive without loss or duplication")
	require.Equal(t, hFallbackDomain, origin.host)
	wantSNI := hFallbackDomain
	if config.noSNI {
		wantSNI = ""
	}
	require.Equal(t, wantSNI, origin.serverName, "the destination rewrite must not rewrite TLS SNI")
	require.Equal(t, uploadBytes.snapshot(), origin.wire, "all client TLS wire bytes must reach origin exactly once, including the sniff cache")
	require.NoError(t, hFallbackReceive(t, routed, "routeConnection result"))
	closeErr := hFallbackReceive(t, closed, "ConnectionManager copy completion")
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) && !errors.Is(closeErr, io.EOF) {
		t.Fatalf("unexpected forwarding completion error: %v", closeErr)
	}
	hFallbackReceive(t, routeDone, "routeConnection exit")
	hFallbackReceive(t, originDone, "origin exit")

	events := trace.snapshot()
	wantStages := []string{"tracker", "connection-manager", "dial"}
	if config.handler {
		wantStages = []string{"tracker", "handler", "connection-manager", "dial"}
	}
	stages := make([]string, len(events))
	for index, event := range events {
		stages[index] = event.stage
	}
	require.Equal(t, wantStages, stages, "guard must precede trackers, handlers and the real ConnectionManager")
	dialDestination := want.Destination
	if len(want.DestinationAddresses) != 0 {
		dialDestination = M.Socksaddr{Addr: want.DestinationAddresses[0], Port: want.Destination.Port}
	}
	actualDialDestination := events[len(events)-1].destination
	t.Logf("HTTPS 200; input=%s Domain=%q; leaf=%s; SNI=%q; upload=%d bytes, exact wire match", initial.Destination, initial.Domain, actualDialDestination, origin.serverName, len(origin.wire))
	require.Equal(t, dialDestination.String(), actualDialDestination.String(), "assert the actual leaf DialContext argument, not only metadata")
	for _, event := range events {
		require.Equal(t, want.Destination, event.metadata.Destination, "%s must observe the post-routing destination", event.stage)
		require.Equal(t, want.RouteOriginalDestination, event.metadata.RouteOriginalDestination, "%s original destination", event.stage)
		require.Equal(t, want.DestinationAddresses, event.metadata.DestinationAddresses, "%s must preserve explicit pins", event.stage)
		require.Equal(t, initial.Destination.Port, event.metadata.Destination.Port, "fallback must not change the port")
		require.Equal(t, initial.IPVersion, event.metadata.IPVersion, "fallback must not relabel the captured IP version")
		require.Equal(t, initial.OriginDestination, event.metadata.OriginDestination)
		require.Equal(t, initial.Source, event.metadata.Source)
	}
	if config.terminal != nil {
		require.NotNil(t, tracker.matched, "the explicit terminal rule must actually have selected the same leaf")
	} else {
		require.Nil(t, tracker.matched)
	}
	if config.selector {
		require.Len(t, events[0].metadata.OutboundChain, 2, "use the real resolveOutbound selector chain")
		require.Equal(t, C.TypeSelector, events[0].metadata.OutboundChain[0].Type())
		require.Same(t, leaf, events[0].metadata.OutboundChain[1])
	} else {
		require.Len(t, events[0].metadata.OutboundChain, 1)
	}
	if perConnection != nil {
		require.Zero(t, perConnection.selectedCalls, "resolveOutbound must never call Selected on per-connection groups")
	}
	if !config.unmatchedSniff && initial.Protocol == "" {
		require.NotEmpty(t, tracker.consumed, "this path must really read and cache the first TLS packet before dispatch")
		require.Equal(t, byte(0x16), tracker.consumed[0])
		require.True(t, bytes.HasPrefix(origin.wire, tracker.consumed))
		require.Equal(t, 1, bytes.Count(origin.wire, tracker.consumed), "the consumed sniff prefix must be forwarded exactly once")
	}
	if config.disable || config.unmatchedSniff || config.failSniff || config.noSNI || initial.Protocol != "" {
		require.Empty(t, events[0].metadata.SniffedDomainForFallbackProxy)
	} else {
		require.Equal(t, hFallbackDomain, events[0].metadata.SniffedDomainForFallbackProxy)
		require.Equal(t, initial.Destination, events[0].metadata.SniffedDestination)
	}
	if config.failSniff {
		require.Error(t, events[0].metadata.SniffError)
	}
	if config.reverseDomain != "" {
		require.Positive(t, dnsRouter.reverseCalls)
		require.Equal(t, config.reverseDomain, events[0].metadata.Domain)
	}
	if config.resolve {
		require.Equal(t, 1, dnsRouter.lookupCalls)
	} else {
		require.Zero(t, dnsRouter.lookupCalls, "the IP fixture must not perform implicit DNS resolution")
	}
}

func TestH_FallbackProxyDomainTLS(t *testing.T) {
	certificate, roots := hFallbackTrust(t)
	for _, test := range []struct {
		name    string
		config  hFallbackTLSConfig
		rewrite bool
	}{
		{"default_vmess", hFallbackTLSConfig{}, true},
		{"selector_to_vmess", hFallbackTLSConfig{selector: true}, true},
		{"selector_to_tcp_handler", hFallbackTLSConfig{selector: true, handler: true}, true},
		{"flag_off_still_https", hFallbackTLSConfig{disable: true}, false},
		{"fake_ip_flag", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) { m.FakeIP = true }}, false},
		{"non_tun", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) { m.InboundType = C.TypeMixed }}, false},
		{"no_dns_association", hFallbackTLSConfig{association: "missing"}, false},
		{"wrong_inbound", hFallbackTLSConfig{association: "wrong_inbound"}, false},
		{"wrong_client", hFallbackTLSConfig{association: "wrong_client"}, false},
		{"wrong_ip", hFallbackTLSConfig{association: "wrong_ip"}, false},
		{"wrong_name", hFallbackTLSConfig{association: "wrong_name"}, false},
		{"expired", hFallbackTLSConfig{association: "expired"}, false},
		{"reverse_domain_without_sniff", hFallbackTLSConfig{unmatchedSniff: true, reverseDomain: hFallbackDomain}, false},
		{"protocol_without_successful_sniff", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) { m.Protocol = C.ProtocolTLS; m.Domain = hFallbackDomain }}, false},
		{"failed_stream_sniff", hFallbackTLSConfig{failSniff: true}, false},
		{"valid_tls_without_sni", hFallbackTLSConfig{noSNI: true}, false},
		{"terminal_ip_cidr_same_vmess", hFallbackTLSConfig{terminal: &option.RawDefaultRule{IPCIDR: badoption.Listable[string]{"203.0.113.0/24"}}}, false},
		{"terminal_ip_version_same_vmess", hFallbackTLSConfig{terminal: &option.RawDefaultRule{IPVersion: 4}}, false},
		{"terminal_domain_same_vmess", hFallbackTLSConfig{terminal: &option.RawDefaultRule{Domain: badoption.Listable[string]{hFallbackDomain}}}, false},
		{"terminal_catch_all_same_vmess", hFallbackTLSConfig{terminal: &option.RawDefaultRule{}}, false},
		{"override_same_address", hFallbackTLSConfig{overrideAddress: hFallbackIP.String()}, false},
		{"override_different_address", hFallbackTLSConfig{overrideAddress: "203.0.113.88"}, false},
		{"override_same_port", hFallbackTLSConfig{overrideSamePort: true}, false},
		{"original_destination_even_same_address", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) { m.RouteOriginalDestination = m.Destination }}, false},
		{"explicit_ip_pin", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) { m.DestinationAddresses = []netip.Addr{m.Destination.Addr} }}, false},
		{"direct_leaf", hFallbackTLSConfig{leafType: C.TypeDirect}, false},
		{"unknown_leaf", hFallbackTLSConfig{leafType: "opaque-test-proxy"}, false},
		{"per_connection_group", hFallbackTLSConfig{perConnection: true, leafType: C.TypeBalancer}, false},
		{"per_connection_proxy_looking_type", hFallbackTLSConfig{perConnection: true}, false},
		{"original_fqdn", hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) {
			m.Destination = M.Socksaddr{Fqdn: hFallbackDomain, Port: m.Destination.Port}
			m.IPVersion = 0
		}}, false},
		{"explicit_resolve_original_fqdn", hFallbackTLSConfig{resolve: true, metadata: func(m *adapter.InboundContext) {
			m.Destination = M.Socksaddr{Fqdn: hFallbackDomain, Port: m.Destination.Port}
			m.IPVersion = 0
		}}, false},
	} {
		t.Run(test.name, func(t *testing.T) { hFallbackRunTLS(t, certificate, roots, test.config, test.rewrite) })
	}
	for _, address := range []string{
		"192.168.1.10", "10.0.0.1", "172.16.0.1", "fd00::1", "127.0.0.1", "::1",
		"169.254.1.10", "fe80::1", "100.64.0.1", "100.127.255.254", "198.18.0.1", "198.19.255.254", "fdfe:dcba:9876::1",
	} {
		t.Run("excluded_"+address, func(t *testing.T) {
			hFallbackRunTLS(t, certificate, roots, hFallbackTLSConfig{metadata: func(m *adapter.InboundContext) {
				m.Destination.Addr = netip.MustParseAddr(address)
				if m.Destination.Addr.Is6() {
					m.IPVersion = 6
				}
			}}, false)
		})
	}
}

func hFallbackGuardMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Inbound: hFallbackInbound, InboundType: C.TypeTun, Network: N.NetworkTCP, IPVersion: 4,
		Source: M.Socksaddr{Addr: hFallbackClient, Port: 32123}, Destination: M.Socksaddr{Addr: hFallbackIP, Port: 443},
		Protocol: C.ProtocolTLS, Domain: "reverse.metadata.is.not.authority.test",
		SniffedDomainForFallbackProxy: hFallbackDomain, SniffedDestination: M.Socksaddr{Addr: hFallbackIP, Port: 443},
	}
}

func TestH_FallbackProxyDomainGuard(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*adapter.InboundContext)
	}{
		{"pre_match", func(m *adapter.InboundContext) { m.PreMatch = true }},
		{"udp_with_tcp_provenance", func(m *adapter.InboundContext) { m.Network = N.NetworkUDP }},
		{"quic", func(m *adapter.InboundContext) { m.Protocol = C.ProtocolQUIC }},
		{"sniff_error_with_stale_provenance", func(m *adapter.InboundContext) { m.SniffError = errors.New("unsuccessful sniff") }},
		{"metadata_domain_only", func(m *adapter.InboundContext) { m.SniffedDomainForFallbackProxy = "" }},
		{"missing_destination_snapshot", func(m *adapter.InboundContext) { m.SniffedDestination = M.Socksaddr{} }},
		{"destination_changed_after_sniff", func(m *adapter.InboundContext) { m.Destination.Addr = netip.MustParseAddr("203.0.113.99") }},
		{"port_changed_after_sniff", func(m *adapter.InboundContext) { m.Destination.Port++ }},
		{"explicit_original_same_destination", func(m *adapter.InboundContext) { m.RouteOriginalDestination = m.Destination }},
		{"explicit_original_other_destination", func(m *adapter.InboundContext) {
			m.RouteOriginalDestination = M.Socksaddr{Addr: netip.MustParseAddr("203.0.113.99"), Port: m.Destination.Port}
		}},
		{"explicit_resolved_pin", func(m *adapter.InboundContext) { m.DestinationAddresses = []netip.Addr{m.Destination.Addr} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := hFallbackGuardMetadata()
			test.mutate(&metadata)
			before := metadata
			router := &Router{}
			associations := newSniffDNSAssociations(16, time.Minute, time.Now)
			// Also authorize the changed IP, so the snapshot gate cannot pass
			// this test accidentally by relying on a missing DNS association.
			associations.record(metadata.Inbound, metadata.Source.Addr, hFallbackDNSAnswer(hFallbackDomain, metadata.Destination.Addr, 30))
			router.sniffDNS.Store(associations)
			router.preserveFallbackProxyDomain(context.Background(), &metadata, nil, []adapter.Outbound{&hFallbackRecordingDialer{outboundType: C.TypeVMess}})
			require.Equal(t, before, metadata, "negative guard must leave all metadata untouched")
		})
	}
	for _, action := range []option.RuleAction{
		{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "fallback-leaf"}},
		{Action: C.RuleActionTypeBypass, BypassOptions: option.RouteActionOptions{Outbound: "fallback-leaf"}},
		{Action: C.RuleActionTypeReject},
		{Action: C.RuleActionTypeHijackDNS},
	} {
		t.Run("selected_terminal_"+action.Action, func(t *testing.T) {
			metadata := hFallbackGuardMetadata()
			before := metadata
			router := &Router{}
			associations := newSniffDNSAssociations(16, time.Minute, time.Now)
			associations.record(metadata.Inbound, metadata.Source.Addr, hFallbackDNSAnswer(hFallbackDomain, metadata.Destination.Addr, 30))
			router.sniffDNS.Store(associations)
			selected := hFallbackNewRule(t, hFallbackRule(action, option.RawDefaultRule{}))
			router.preserveFallbackProxyDomain(context.Background(), &metadata, selected, []adapter.Outbound{&hFallbackRecordingDialer{outboundType: C.TypeVMess}})
			require.Equal(t, before, metadata)
		})
	}
	for _, protocol := range []string{C.ProtocolTLS, C.ProtocolHTTP} {
		t.Run("only_destination_fields_change_"+protocol, func(t *testing.T) {
			metadata := hFallbackGuardMetadata()
			metadata.Protocol = protocol
			want := metadata
			want.RouteOriginalDestination = metadata.Destination
			want.Destination = M.Socksaddr{Fqdn: hFallbackDomain, Port: metadata.Destination.Port}
			router := &Router{}
			associations := newSniffDNSAssociations(16, time.Minute, time.Now)
			associations.record(metadata.Inbound, metadata.Source.Addr, hFallbackDNSAnswer(hFallbackDomain, metadata.Destination.Addr, 30))
			router.sniffDNS.Store(associations)
			router.preserveFallbackProxyDomain(context.Background(), &metadata, nil, []adapter.Outbound{&hFallbackRecordingDialer{outboundType: C.TypeVMess}})
			require.Equal(t, want, metadata, "port, IPVersion, routing caches and unrelated metadata must be preserved")
		})
	}
}

// Capture an actual crypto/tls ClientHello. The intentional EOF only ends this
// capture (there is no TLS server here); its handshake goroutine is always joined.
func hFallbackCaptureHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	require.NoError(t, client.SetDeadline(time.Now().Add(hFallbackTimeout)))
	require.NoError(t, server.SetDeadline(time.Now().Add(hFallbackTimeout)))
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		done <- tls.Client(client, &tls.Config{ServerName: serverName, RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}).Handshake()
	}()
	t.Cleanup(func() {
		hFallbackClose(t, client)
		hFallbackClose(t, server)
		hFallbackReceive(t, exited, "ClientHello capture goroutine")
	})
	header := make([]byte, 5)
	_, err := io.ReadFull(server, header)
	require.NoError(t, err)
	require.Equal(t, byte(0x16), header[0])
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(server, body)
	require.NoError(t, err)
	hFallbackClose(t, server)
	hFallbackClose(t, client)
	require.Error(t, hFallbackReceive(t, done, "ClientHello capture handshake"), "capture deliberately has no server response")
	return append(header, body...)
}

func hFallbackAddECH(t *testing.T, hello []byte) []byte {
	t.Helper()
	// Preserve the real ClientHello, adding only a structurally valid outer ECH
	// extension. This is a parser/gate fixture, not an ECH handshake simulation.
	hello = bytes.Clone(hello)
	index := 9 + 34
	require.Less(t, index, len(hello))
	index += 1 + int(hello[index])
	require.Less(t, index+2, len(hello))
	index += 2 + int(binary.BigEndian.Uint16(hello[index:]))
	require.Less(t, index, len(hello))
	index += 1 + int(hello[index])
	require.Equal(t, len(hello), index+2+int(binary.BigEndian.Uint16(hello[index:])))
	ech := []byte{0, 0, 1, 0, 1, 42, 0, 32}
	ech = append(ech, bytes.Repeat([]byte{0x11}, 32)...)
	ech = binary.BigEndian.AppendUint16(ech, 32)
	ech = append(ech, bytes.Repeat([]byte{0x22}, 32)...)
	extension := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(ech)))
	extension = append(extension, ech...)
	binary.BigEndian.PutUint16(hello[index:], binary.BigEndian.Uint16(hello[index:])+uint16(len(extension)))
	hello = append(hello, extension...)
	binary.BigEndian.PutUint16(hello[3:], uint16(len(hello)-5))
	handshakeLength := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength)
	return hello
}

func TestH_FallbackProxyDomainSniffProvenance(t *testing.T) {
	hello := hFallbackCaptureHello(t, hFallbackDomain)
	noSNI := hFallbackCaptureHello(t, hFallbackIP.String())
	for _, test := range []struct {
		name                  string
		payload               []byte
		disable, fail, forged bool
		prefix                int
		want                  string
	}{
		{"real_tls", hello, false, false, false, 0, hFallbackDomain},
		{"multiple_cached_buffers", hello, false, false, false, 3, hFallbackDomain},
		{"independent_of_metadata_domain", hello, false, false, true, 0, hFallbackDomain},
		{"flag_off", hello, true, false, false, 0, ""},
		{"no_sni", noSNI, false, false, false, 0, ""},
		{"ech_outer_name_not_authority", hFallbackAddECH(t, hello), false, false, false, 0, ""},
		{"truncated_hello", hello[:len(hello)-2], false, true, false, 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := hFallbackGuardMetadata()
			metadata.Protocol = ""
			metadata.SniffedDomainForFallbackProxy = "stale.provenance.example.test"
			metadata.SniffedDestination = M.Socksaddr{}
			rule := hFallbackNewRule(t, hFallbackSniffRule(!test.disable))
			action := rule.Action().(*R.RuleActionSniff)
			if test.forged {
				action.StreamSniffers = []sniff.StreamSniffer{func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
					if err := sniff.TLSClientHello(ctx, metadata, reader); err != nil {
						return err
					}
					metadata.Domain = "forged.metadata.example.test"
					return nil
				}}
			}
			var prefix []*buf.Buffer
			if test.prefix != 0 {
				prefix = []*buf.Buffer{buf.As(bytes.Clone(test.payload[:test.prefix]))}
				t.Cleanup(func() { buf.ReleaseMulti(prefix) })
			}
			router := &Router{logger: log.NewNOPFactory().NewLogger("sniff")}
			buffer, packets, fatalErr := router.actionSniff(context.Background(), &metadata, action, SBufio.NewReadOnlyConn(bytes.NewReader(test.payload[test.prefix:])), nil, prefix, nil)
			require.NoError(t, fatalErr)
			require.Empty(t, packets)
			require.NotNil(t, buffer)
			t.Cleanup(buffer.Release)
			require.Equal(t, test.payload[test.prefix:], buffer.Bytes(), "sniff must not consume or modify the forwarding cache")
			if test.prefix != 0 {
				require.Equal(t, test.payload[:test.prefix], prefix[0].Bytes())
			}
			if test.fail {
				require.Error(t, metadata.SniffError)
			} else {
				require.NoError(t, metadata.SniffError, "negative ECH/no-SNI cases must not merely depend on a failed ordinary sniff")
				require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			}
			require.Equal(t, test.want, metadata.SniffedDomainForFallbackProxy)
			if test.fail || test.disable {
				require.False(t, metadata.SniffedDestination.IsValid())
			} else {
				require.Equal(t, metadata.Destination, metadata.SniffedDestination)
			}
			before := metadata
			associations := newSniffDNSAssociations(16, time.Minute, time.Now)
			associations.record(metadata.Inbound, metadata.Source.Addr, hFallbackDNSAnswer(hFallbackDomain, metadata.Destination.Addr, 30))
			router.sniffDNS.Store(associations)
			router.preserveFallbackProxyDomain(context.Background(), &metadata, nil, []adapter.Outbound{&hFallbackRecordingDialer{outboundType: C.TypeVMess}})
			if test.want == "" {
				require.Equal(t, before, metadata, "no SNI, ECH, failure and disabled sniff must not authorize a rewrite")
			} else {
				require.Equal(t, M.Socksaddr{Fqdn: test.want, Port: before.Destination.Port}, metadata.Destination)
			}
		})
	}

	t.Run("http_host_from_cached_bytes", func(t *testing.T) {
		payload := []byte("GET / HTTP/1.1\r\nHost: " + strings.ToUpper(hFallbackDomain) + "\r\n\r\n")
		options := hFallbackSniffRule(true)
		options.DefaultOptions.SniffOptions.Sniffer = badoption.Listable[string]{C.ProtocolHTTP}
		action := hFallbackNewRule(t, options).Action().(*R.RuleActionSniff)
		metadata := hFallbackGuardMetadata()
		metadata.Protocol = ""
		router := &Router{logger: log.NewNOPFactory().NewLogger("sniff")}
		buffer, _, err := router.actionSniff(context.Background(), &metadata, action, SBufio.NewReadOnlyConn(bytes.NewReader(payload)), nil, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, buffer)
		t.Cleanup(buffer.Release)
		require.NoError(t, metadata.SniffError)
		require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
		require.Equal(t, hFallbackDomain, metadata.SniffedDomainForFallbackProxy)
		require.Equal(t, payload, buffer.Bytes())
	})
}

// This finite packet fixture has no background readers or outbound UDP dialer.
// It lets the real packet sniff/cache/dispatch path prove that TCP preservation
// does not grow pretend support for UDP or QUIC destination transformation.
type hFallbackOnePacket struct {
	mu          sync.Mutex
	payload     []byte
	destination M.Socksaddr
	reads       int
	closed      bool
}

func (p *hFallbackOnePacket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.reads != 0 {
		return M.Socksaddr{}, io.EOF
	}
	p.reads++
	_, err := buffer.Write(p.payload)
	return p.destination, err
}
func (*hFallbackOnePacket) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return errors.New("one-way packet fixture does not write packets")
}
func (p *hFallbackOnePacket) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
func (p *hFallbackOnePacket) LocalAddr() net.Addr            { return p.destination.UDPAddr() }
func (*hFallbackOnePacket) SetDeadline(time.Time) error      { return nil }
func (*hFallbackOnePacket) SetReadDeadline(time.Time) error  { return nil }
func (*hFallbackOnePacket) SetWriteDeadline(time.Time) error { return nil }

type hFallbackPacketHandler struct {
	*hFallbackRecordingDialer
	metadata    adapter.InboundContext
	payload     []byte
	destination M.Socksaddr
	err         error
}

func (h *hFallbackPacketHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.metadata = metadata
	buffer := buf.NewPacket()
	defer buffer.Release()
	h.destination, h.err = conn.ReadPacket(buffer)
	h.payload = bytes.Clone(buffer.Bytes())
	h.err = errors.Join(h.err, conn.Close())
	onClose(h.err)
}

func TestH_FallbackProxyDomainPacketDispatchUnchanged(t *testing.T) {
	// Existing sniff/quic_test.go's complete Chrome 115 Initial capture. It is
	// parsed offline, never sent to its original host or to any network.
	const quicInitial = "cb0000000108181e17c387120abc000044d0705b6a3ef9ee37a8d3949a7d393ed078243c2ee2c3627fad1c3f107c117f4f071131ad61848068fcbbe5c65803c147f7f8ec5e2cd77b77beea23ba779d936dccac540f8396400e3190ea35cc2942af4171a04cb14272491920f90124959f44e80143678c0b52f5d31af319aaa589db2f940f004562724d0af40f737e1bb0002a071e6a1dbc9f52c64f070806a5010abed0298053634d9c9126bd7949ae5087998ade762c0ad06691d99c0875a38c601fc1ee77bfc3b8c11381829f2c9bdd022f4499c43ff1d6aee1a0d296861461dda217d22c568b276016ef3929e59d2f7d7ddf7809920fb7dc805641608949f3f8466ab3d37149aac501f0b107d808f3add4acfc657e4a82e2b88e97a6c74a00c419548760ab3414ba13915c78a1ca79dceee8d59fbe299f20b671ac44823218368b2a026baa55170cf549519ac21dbb6d31d248bd339438a4e663bcdca1fe3ae3f045a5dc19b122e9db9d7af9757076666dda4e9ace1c67def77fa14786f0cab3ebf7a270ea6e2b37838318c95779f80c3b8471948d0046c3614b3a13477c939a39a7855d85d13522a45ae0765739cd5eedef87237e824a929983ace27640c6495dbf5a72fa0b96893dc5d28f3988249a57bdb458d460b4a57043de3da750a76b6e5d2259247ca27cd864ea18f0d09aa62ab6eb7c014fb43179b2a1963d170b756cce83eeaebff78a828d025c811848e16ff862a8080d093478cd2208c8ab0803178325bc0d9d6bb25e62fa50c4ad15cf80916da6578796932036c72e43eb480d1e423ed812ac75a97722f8416529b82ba8ee2219c535012282bb17066bd53e78b87a71abdb7ebdb2a7c2766ff8397962e87d0f85485b64b4ee81cc84f99c47f33f2b0872716441992773f59186e38d32dbf5609a6fda94cb928cd25f5a7a3ab736b5a4236b6d5409ab18892c6a4d3480fc2350abfdf0bab1cedb55bdf0760fdb703e6688f4de596254eed4ed3e67eb03d0717b8e15b31e735214e588c87ae36bc6c310e1894b4c15143e4ccf287b2dbc707a946bf9671ae3c574f9486b2c82eec784bba4cbc76113cbe0f97ac8c13cfa38f2925ab9d06887a612ce48280a91d7e074e6caf898d88e2bbf71360899abf48a03f9a70cf2891199f2d63b116f4871af0ebb4f4906792f66cc21d1609f189138532875c129a68c73e7bcd3b5d8100beac1d8ac4b20d94a59ac8df5a5af58a9acb20413eadf97189f5f19ff889155f0c4d37514ec184eb6903967ff38a41fc087abb0f2cad3761d6e3f95f92a09a72f5c065b16e188088b87460241f27ecdb1bc6ece92c8d36b2d68b58d0fb4d4b3c928c579ade8ae5a995833aadd297c30a37f7bc35440fc97070e1b198e0fac00157452177d16d2803b4239997452b4ad3a951173bdec47a033fd7f8a7942accaa9aaa905b3c5a2175e7c3e07c48bf25331727fd69cd1e64d74d8c9d4a6f8f4491adb7bc911505cb19877083d8f21a12475e313fccf57877ff3556318e81ed9145dd9427f2b65275440893035f417481f721c69215af8ae103530cd0a1d35bf2cb5a27628f8d44d7c6f5ec12ce79d0a8333e0eb48771115d0a191304e46b8db19bbe5c40f1c346dde98e76ff5e21ff38d2c34e60cb07766ed529dd6d2cbacd7fbf1ed8a0e6e40decad0ca5021e91552be87c156d3ae2fffef41c65b14ba6d488f2c3227a1ab11ffce0e2dc47723a69da27a67a7f26e1cb13a7103af9b87a8db8e18ea"
	quicPayload, err := hex.DecodeString(quicInitial)
	require.NoError(t, err)
	for _, test := range []struct {
		name, domain string
		payload      []byte
		quic         bool
	}{
		{"opaque_udp_even_with_tcp_provenance", hFallbackDomain, []byte("unchanged UDP payload"), false},
		{"real_quic_initial", "www.google.com", quicPayload, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := hFallbackGuardMetadata()
			metadata.Network = N.NetworkUDP
			if test.quic {
				metadata.Protocol, metadata.Domain, metadata.SniffedDomainForFallbackProxy = "", "", ""
				metadata.SniffedDestination = M.Socksaddr{}
			}
			initial := metadata
			packet := &hFallbackOnePacket{payload: test.payload, destination: metadata.Destination}
			t.Cleanup(func() { hFallbackClose(t, packet) })
			trace := &hFallbackTrace{}
			handler := &hFallbackPacketHandler{hFallbackRecordingDialer: &hFallbackRecordingDialer{outboundType: C.TypeVMess, trace: trace}}
			tracker := &hFallbackTracker{trace: trace}
			router := &Router{
				ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("packet"),
				dns: &hFallbackDNSRouter{}, dnsTransport: &hFallbackDNSTransports{},
				outbound: &hFallbackOutboundManager{selected: handler}, trackers: []adapter.ConnectionTracker{tracker},
			}
			options := hFallbackSniffRule(true)
			options.DefaultOptions.SniffOptions.Sniffer = badoption.Listable[string]{C.ProtocolQUIC}
			require.NoError(t, router.Initialize([]option.Rule{options}, nil))
			t.Cleanup(func() { require.NoError(t, router.Close()) })
			router.sniffDNS.Load().record(metadata.Inbound, metadata.Source.Addr, hFallbackDNSAnswer(test.domain, metadata.Destination.Addr, 30))
			require.True(t, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, test.domain, metadata.Destination.Addr))
			closed := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), hFallbackTimeout)
			defer cancel()
			require.NoError(t, router.routePacketConnection(ctx, packet, metadata, func(err error) { closed <- err }))
			require.NoError(t, hFallbackReceive(t, closed, "packet handler completion"))
			require.NoError(t, handler.err)
			require.Equal(t, test.payload, handler.payload, "a cached QUIC Initial must also be delivered exactly once")
			require.Equal(t, initial.Destination, handler.destination)
			require.Equal(t, initial.Destination, handler.metadata.Destination)
			require.Equal(t, initial.RouteOriginalDestination, handler.metadata.RouteOriginalDestination)
			require.Equal(t, initial.IPVersion, handler.metadata.IPVersion)
			require.Equal(t, N.NetworkUDP, handler.metadata.Network)
			require.Equal(t, initial.SniffedDomainForFallbackProxy, handler.metadata.SniffedDomainForFallbackProxy)
			require.Equal(t, initial.SniffedDestination, handler.metadata.SniffedDestination)
			require.Len(t, trace.snapshot(), 1)
			require.Equal(t, initial.Destination, trace.snapshot()[0].metadata.Destination)
			if test.quic {
				require.NoError(t, handler.metadata.SniffError)
				require.Equal(t, C.ProtocolQUIC, handler.metadata.Protocol)
				require.Equal(t, test.domain, handler.metadata.Domain)
			}
			packet.mu.Lock()
			reads, wasClosed := packet.reads, packet.closed
			packet.mu.Unlock()
			require.Equal(t, 1, reads)
			require.True(t, wasClosed)
		})
	}
}
