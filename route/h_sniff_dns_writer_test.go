package route

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func hServedDNSFixture() (adapter.InboundContext, *mDNS.Msg, *mDNS.Msg, netip.Addr) {
	metadata := adapter.InboundContext{
		Inbound: "test-tun", InboundType: C.TypeTun,
		Source: M.ParseSocksaddr("192.0.2.2:54000"), Destination: M.ParseSocksaddr("192.0.2.1:53"),
	}
	query := new(mDNS.Msg).SetQuestion("origin.test.", mDNS.TypeA)
	response := new(mDNS.Msg).SetReply(query)
	address := netip.MustParseAddr("203.0.113.34")
	response.Answer = []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{Name: "origin.test.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 3600},
		A:   net.IP(address.AsSlice()),
	}}
	return metadata, query, response, address
}

func hServedDNSRouter() *Router {
	router := new(Router)
	router.sniffDNS.Store(newSniffDNSAssociations(8, 5*time.Minute, time.Now))
	return router
}

func hServedDNSWire(t *testing.T, response *mDNS.Msg) []byte {
	t.Helper()
	wire, err := response.Pack()
	require.NoError(t, err)
	return wire
}

func hServedDNSReceive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("DNS fixture did not complete")
		var zero T
		return zero
	}
}

type hServedPacketWriter struct {
	wire        []byte
	destination M.Socksaddr
	err         error
	front       int
	rear        int
	beforeWrite func()
}

func (w *hServedPacketWriter) FrontHeadroom() int { return 13 }
func (w *hServedPacketWriter) RearHeadroom() int  { return 17 }

func (w *hServedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if w.beforeWrite != nil {
		w.beforeWrite()
	}
	w.wire = append([]byte(nil), buffer.Bytes()...)
	w.destination = destination
	w.front, w.rear = buffer.Start(), buffer.FreeLen()
	buffer.ExtendHeader(w.FrontHeadroom())
	buffer.Extend(w.RearHeadroom())
	clear(buffer.Bytes())
	buffer.Release()
	return w.err
}

func TestH_SniffDNSPacketDelivery(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("fixture write failed"), io.ErrShortWrite} {
		name := "success"
		if writeErr != nil {
			name = writeErr.Error()
		}
		t.Run(name, func(t *testing.T) {
			router := hServedDNSRouter()
			metadata, query, response, address := hServedDNSFixture()
			sink := &hServedPacketWriter{err: writeErr, beforeWrite: func() {
				require.False(t, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			}}
			handler := router.sniffDNSObserver(metadata)()
			err := dnsOutbound.WritePacketResponseWithResponseObserver(query, response, sink, metadata.Destination, handler)
			require.ErrorIs(t, err, writeErr)
			require.Equal(t, metadata.Destination, sink.destination)
			var delivered mDNS.Msg
			require.NoError(t, delivered.Unpack(sink.wire))
			require.Equal(t, uint32(300), delivered.Answer[0].Header().Ttl)
			require.Equal(t, uint32(3600), response.Answer[0].Header().Ttl, "upstream/cache object was mutated")
			require.Equal(t, writeErr == nil, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			require.GreaterOrEqual(t, sink.front, sink.FrontHeadroom())
			require.GreaterOrEqual(t, sink.rear, sink.RearHeadroom())
		})
	}
}

func TestH_SniffDNSDeliveredTTLAndOPTFlags(t *testing.T) {
	metadata, query, response, address := hServedDNSFixture()
	response.Answer = append(response.Answer, &mDNS.TXT{
		Hdr: mDNS.RR_Header{Name: "origin.test.", Rrtype: mDNS.TypeTXT, Class: mDNS.ClassINET, Ttl: 23}, Txt: []string{"unchanged"},
	})
	response.Ns = []mDNS.RR{&mDNS.SOA{
		Hdr: mDNS.RR_Header{Name: "test.", Rrtype: mDNS.TypeSOA, Class: mDNS.ClassINET, Ttl: 7200},
		Ns:  "ns.test.", Mbox: "hostmaster.test.", Serial: 7, Refresh: 9, Retry: 11, Expire: 86400, Minttl: 1800,
	}}
	response.Extra = []mDNS.RR{&mDNS.AAAA{
		Hdr: mDNS.RR_Header{Name: "ns.test.", Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 86400}, AAAA: net.ParseIP("2001:db8::53"),
	}}
	response.SetEdns0(1232, true)
	response.IsEdns0().SetVersion(1)
	response.IsEdns0().SetZ(0x0023)
	response.IsEdns0().Option = []mDNS.EDNS0{&mDNS.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 3, 7}}}
	response.Rcode = mDNS.RcodeBadVers
	// Keep extended Rcode and every EDNS flag in the actual original wire.
	originalWire := hServedDNSWire(t, response)
	var original mDNS.Msg
	require.NoError(t, original.Unpack(originalWire))
	now := time.Unix(1000, 0)
	router := new(Router)
	table := newSniffDNSAssociations(8, 300*time.Second+900*time.Millisecond, func() time.Time { return now })
	router.sniffDNS.Store(table)
	replacement, complete := router.sniffDNSObserver(metadata)()(originalWire)
	require.NotNil(t, replacement)
	require.LessOrEqual(t, len(replacement), len(originalWire))
	var delivered mDNS.Msg
	require.NoError(t, delivered.Unpack(replacement))
	require.Equal(t, original.MsgHdr, delivered.MsgHdr)
	require.Equal(t, original.Question, delivered.Question)
	require.Equal(t, original.IsEdns0(), delivered.IsEdns0())
	for index, section := range [][]mDNS.RR{original.Answer, original.Ns, original.Extra} {
		actual := [][]mDNS.RR{delivered.Answer, delivered.Ns, delivered.Extra}[index]
		require.Len(t, actual, len(section))
		for rrIndex, rr := range section {
			expected := mDNS.Copy(rr)
			if expected.Header().Rrtype != mDNS.TypeOPT {
				expected.Header().Ttl = min(expected.Header().Ttl, 300)
			}
			// RDLENGTH describes the wire encoding, not record content; name
			// compression can shorten it without changing any RDATA field.
			expected.Header().Rdlength = actual[rrIndex].Header().Rdlength
			require.Equal(t, expected, actual[rrIndex])
		}
	}
	require.Equal(t, originalWire, hServedDNSWire(t, response))
	complete(nil)
	require.False(t, table.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address), "extended negative Rcode must not authorize")

	// A successful 3600-second answer is delivered and recorded for the same
	// whole-second cap, not 300.9 seconds in one place and 3600 in the other.
	response.Rcode = mDNS.RcodeSuccess
	sink := new(hServedPacketWriter)
	require.NoError(t, dnsOutbound.WritePacketResponseWithResponseObserver(query, response, sink, metadata.Destination, router.sniffDNSObserver(metadata)()))
	require.NoError(t, delivered.Unpack(sink.wire))
	require.Equal(t, uint32(300), delivered.Answer[0].Header().Ttl)
	now = now.Add(299*time.Second + 999*time.Millisecond)
	require.True(t, table.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	now = now.Add(time.Millisecond)
	require.False(t, table.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
}

func TestH_SniffDNSShortAndZeroTTLNeverExtended(t *testing.T) {
	for _, ttl := range []uint32{0, 1, 29, 300, 3600, 86400, 1 << 31} {
		t.Run((time.Duration(ttl) * time.Second).String(), func(t *testing.T) {
			router := hServedDNSRouter()
			metadata, query, response, address := hServedDNSFixture()
			response.Answer[0].Header().Ttl = ttl
			sink := new(hServedPacketWriter)
			require.NoError(t, dnsOutbound.WritePacketResponseWithResponseObserver(query, response, sink, metadata.Destination, router.sniffDNSObserver(metadata)()))
			var delivered mDNS.Msg
			require.NoError(t, delivered.Unpack(sink.wire))
			expected := min(ttl, 300)
			if ttl >= 1<<31 {
				expected = 0
			}
			require.Equal(t, expected, delivered.Answer[0].Header().Ttl)
			require.Equal(t, expected > 0, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
		})
	}
}

func TestH_SniffDNSTruncatedPacketDoesNotAuthorize(t *testing.T) {
	router := hServedDNSRouter()
	metadata, query, response, address := hServedDNSFixture()
	for range 8 {
		response.Answer = append(response.Answer, &mDNS.TXT{
			Hdr: mDNS.RR_Header{Name: "origin.test.", Rrtype: mDNS.TypeTXT, Class: mDNS.ClassINET, Ttl: 3600},
			Txt: []string{string(bytes.Repeat([]byte{'a'}, 200))},
		})
	}
	sink := new(hServedPacketWriter)
	require.NoError(t, dnsOutbound.WritePacketResponseWithResponseObserver(query, response, sink, metadata.Destination, router.sniffDNSObserver(metadata)()))
	var delivered mDNS.Msg
	require.NoError(t, delivered.Unpack(sink.wire))
	require.True(t, delivered.Truncated)
	require.LessOrEqual(t, len(sink.wire), 512)
	require.False(t, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	for _, rr := range delivered.Answer {
		require.LessOrEqual(t, rr.Header().Ttl, uint32(300))
	}
}

func TestH_SniffDNSRepackGrowthUsesLengthPreservingTTLRewrite(t *testing.T) {
	router := hServedDNSRouter()
	metadata, _, response, address := hServedDNSFixture()
	response.Compress = true
	response.Truncated = true
	response.Ns = []mDNS.RR{&mDNS.SRV{
		Hdr:  mDNS.RR_Header{Name: "_service._tcp.origin.test.", Rrtype: mDNS.TypeSRV, Class: mDNS.ClassINET, Ttl: 86400},
		Port: 443, Target: "origin.test.",
	}}
	wire := hServedDNSWire(t, response)
	var parsed mDNS.Msg
	require.NoError(t, parsed.Unpack(wire))
	offsets, valid := sniffDNSResponseTTLOffsets(wire, &parsed)
	require.True(t, valid)
	require.Len(t, offsets, 2)
	// Unpack tolerates a compressed SRV target, while Pack emits it without
	// compression. This deliberately noncanonical TC fixture exercises growth
	// without allowing the parser-tolerated packet to authorize any address.
	srvTTL := offsets[1]
	targetStart := srvTTL + 6 + 6 // TTL + RDLENGTH + priority/weight/port
	compact := append(append([]byte(nil), wire[:targetStart]...), 0xc0, 0x0c)
	binary.BigEndian.PutUint16(compact[srvTTL+4:], 8)
	require.NoError(t, parsed.Unpack(compact))
	parsed.Compress = true
	require.Greater(t, len(hServedDNSWire(t, &parsed)), len(compact))
	replacement, complete := router.sniffDNSObserver(metadata)()(compact)
	expected := append([]byte(nil), compact...)
	for _, offset := range offsets {
		binary.BigEndian.PutUint32(expected[offset:], 300)
	}
	require.Equal(t, expected, replacement, "fallback must change only fixed-width TTLs")
	require.Len(t, replacement, len(compact))
	complete(nil)
	require.False(t, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
}

func TestH_SniffDNSNegativeDeliveryRevokesOnlyAfterSuccess(t *testing.T) {
	for _, rcode := range []int{mDNS.RcodeSuccess, mDNS.RcodeNameError, mDNS.RcodeServerFailure} {
		for _, fail := range []bool{false, true} {
			t.Run(mDNS.RcodeToString[rcode]+map[bool]string{false: "/delivered", true: "/failed"}[fail], func(t *testing.T) {
				router := hServedDNSRouter()
				metadata, query, response, address := hServedDNSFixture()
				table := router.sniffDNS.Load()
				table.record(metadata.Inbound, metadata.Source.Addr, response)
				require.True(t, table.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
				negative := new(mDNS.Msg).SetReply(query)
				negative.Rcode = rcode
				sink := new(hServedPacketWriter)
				if fail {
					sink.err = errors.New("negative response not delivered")
				}
				require.ErrorIs(t, dnsOutbound.WritePacketResponseWithResponseObserver(query, negative, sink, metadata.Destination, router.sniffDNSObserver(metadata)()), sink.err)
				var delivered mDNS.Msg
				require.NoError(t, delivered.Unpack(sink.wire))
				require.Equal(t, rcode, delivered.Rcode)
				require.Empty(t, delivered.Answer)
				require.Equal(t, fail, table.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			})
		}
	}
}

func TestH_SniffDNSObserverEligibilityAndMalformedWire(t *testing.T) {
	metadata, _, response, address := hServedDNSFixture()
	router := new(Router)
	factory := router.sniffDNSObserver(metadata)
	require.NotNil(t, factory, "a disabled connection must retain a factory for off-to-on reload")
	require.Nil(t, factory())
	router.sniffDNS.Store(newSniffDNSAssociations(8, time.Minute, time.Now))
	mixed := metadata
	mixed.InboundType = C.TypeMixed
	require.Nil(t, router.sniffDNSObserver(mixed))
	for _, source := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.MustParseAddr("::ffff:192.0.2.2"), netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("ff02::1")} {
		invalid := metadata
		invalid.Source.Addr = source
		require.Nil(t, router.sniffDNSObserver(invalid))
	}
	wire := hServedDNSWire(t, response)
	incorrectCount := append([]byte(nil), wire...)
	binary.BigEndian.PutUint16(incorrectCount[6:], 2)
	for _, invalid := range [][]byte{nil, {1, 2, 3}, wire[:len(wire)-1], append(append([]byte(nil), wire...), 0), incorrectCount} {
		replacement, complete := factory()(invalid)
		require.Nil(t, replacement)
		require.Nil(t, complete)
		require.False(t, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	}
}

type hServedExchange struct {
	query   *mDNS.Msg
	respond func(*mDNS.Msg, error)
}

type hServedExchangeRouter struct {
	adapter.DNSRouter
	requests chan hServedExchange
}

func (r *hServedExchangeRouter) ExchangeAsync(_ context.Context, message *mDNS.Msg, _ adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	r.requests <- hServedExchange{message.Copy(), callback}
}

type hServedStreamConn struct {
	net.Conn
	reader *bytes.Buffer
	writes chan []byte
	short  bool
	err    error
}

func (c *hServedStreamConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *hServedStreamConn) Write(p []byte) (int, error) {
	n := len(p)
	if c.short {
		n = min(n, 5)
	}
	c.writes <- append([]byte(nil), p[:n]...)
	clear(p)
	return n, c.err
}

func TestH_SniffDNSStreamDeliverySuccessFailureAndShortWrite(t *testing.T) {
	for _, outcome := range []string{"success", "write-error", "short-write"} {
		t.Run(outcome, func(t *testing.T) {
			metadata, query, response, address := hServedDNSFixture()
			router := hServedDNSRouter()
			resolver := &hServedExchangeRouter{requests: make(chan hServedExchange, 1)}
			conn := &hServedStreamConn{reader: new(bytes.Buffer), writes: make(chan []byte, 1)}
			var wantErr error
			switch outcome {
			case "write-error":
				wantErr = errors.New("stream response delivery failed")
				conn.err = wantErr
			case "short-write":
				conn.short = true
				wantErr = io.ErrShortWrite
			}
			completed := make(chan error, 1)
			factory := router.sniffDNSObserver(metadata)
			trackedFactory := func() dnsOutbound.ResponseHandler {
				handler := factory()
				return func(wire []byte) ([]byte, func(error)) {
					replacement, complete := handler(wire)
					return replacement, func(err error) {
						complete(err)
						completed <- err
					}
				}
			}
			wire := hServedDNSWire(t, query)
			frame := make([]byte, 2+len(wire))
			binary.BigEndian.PutUint16(frame, uint16(len(wire)))
			copy(frame[2:], wire)
			conn.reader.Write(frame)
			require.NoError(t, dnsOutbound.HandleStreamDNSRequestWithResponseObserver(context.Background(), resolver, conn, metadata, trackedFactory))
			hServedDNSReceive(t, resolver.requests).respond(response, nil)
			hServedDNSReceive(t, conn.writes)
			require.ErrorIs(t, hServedDNSReceive(t, completed), wantErr)
			require.Equal(t, wantErr == nil, router.sniffDNS.Load().matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			require.Empty(t, completed, "completion was called more than once")
		})
	}
}

func TestH_SniffDNSLongConnectionReloadCapturesEachQuery(t *testing.T) {
	for _, initiallyEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "off-to-on", true: "enabled-to-enabled"}[initiallyEnabled], func(t *testing.T) {
			metadata, query, response, address := hServedDNSFixture()
			router := new(Router)
			var old *sniffDNSAssociations
			if initiallyEnabled {
				old = newSniffDNSAssociations(8, 5*time.Minute, time.Now)
				router.sniffDNS.Store(old)
			}
			factory := router.sniffDNSObserver(metadata)
			completed := make(chan struct{}, 2)
			trackedFactory := func() dnsOutbound.ResponseHandler {
				handler := factory()
				if handler == nil {
					return nil
				}
				return func(wire []byte) ([]byte, func(error)) {
					replacement, complete := handler(wire)
					return replacement, func(err error) {
						if complete != nil {
							complete(err)
						}
						completed <- struct{}{}
					}
				}
			}
			resolver := &hServedExchangeRouter{requests: make(chan hServedExchange, 2)}
			conn := &hServedStreamConn{reader: new(bytes.Buffer), writes: make(chan []byte, 2)}
			submit := func() hServedExchange {
				wire := hServedDNSWire(t, query)
				frame := make([]byte, 2+len(wire))
				binary.BigEndian.PutUint16(frame, uint16(len(wire)))
				copy(frame[2:], wire)
				conn.reader.Write(frame)
				require.NoError(t, dnsOutbound.HandleStreamDNSRequestWithResponseObserver(context.Background(), resolver, conn, metadata, trackedFactory))
				return hServedDNSReceive(t, resolver.requests)
			}
			inFlight := submit()
			current := newSniffDNSAssociations(8, 5*time.Minute, time.Now)
			router.sniffDNS.Store(current)
			afterReload := submit()
			inFlight.respond(response.Copy(), nil)
			oldFrame := hServedDNSReceive(t, conn.writes)
			if initiallyEnabled {
				hServedDNSReceive(t, completed)
				require.True(t, old.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			}
			require.False(t, current.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
			var oldDelivered mDNS.Msg
			require.NoError(t, oldDelivered.Unpack(oldFrame[2:]))
			require.Equal(t, map[bool]uint32{false: 3600, true: 300}[initiallyEnabled], oldDelivered.Answer[0].Header().Ttl)
			afterReload.respond(response.Copy(), nil)
			newFrame := hServedDNSReceive(t, conn.writes)
			hServedDNSReceive(t, completed)
			require.Equal(t, len(newFrame)-2, int(binary.BigEndian.Uint16(newFrame)))
			require.True(t, current.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
		})
	}
}

func TestH_SniffDNSOptimizedHijackCapturesBeforeExchange(t *testing.T) {
	metadata, query, response, address := hServedDNSFixture()
	router := hServedDNSRouter()
	resolver := &hServedExchangeRouter{requests: make(chan hServedExchange, 2)}
	router.dns = resolver
	old := router.sniffDNS.Load()
	firstSink := new(hServedPacketWriter)
	router.HijackDNSPacket(context.Background(), hServedDNSWire(t, query), firstSink, metadata)
	inFlight := hServedDNSReceive(t, resolver.requests)
	current := newSniffDNSAssociations(8, 5*time.Minute, time.Now)
	router.sniffDNS.Store(current)
	secondSink := new(hServedPacketWriter)
	router.HijackDNSPacket(context.Background(), hServedDNSWire(t, query), secondSink, metadata)
	afterReload := hServedDNSReceive(t, resolver.requests)
	inFlight.respond(response.Copy(), nil)
	require.True(t, old.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	require.False(t, current.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	afterReload.respond(response.Copy(), nil)
	require.True(t, current.matches(metadata.Inbound, metadata.Source.Addr, "origin.test", address))
	require.Equal(t, metadata.Destination, secondSink.destination)
}

func TestH_SniffDNSDefaultPacketResponseUnchanged(t *testing.T) {
	metadata, query, response, _ := hServedDNSFixture()
	router := new(Router)
	legacy := new(hServedPacketWriter)
	require.NoError(t, router.writeDNSPacketResponse(query, response, legacy, metadata.Destination))
	observed := new(hServedPacketWriter)
	factory := router.sniffDNSObserver(metadata)
	require.Nil(t, factory())
	require.NoError(t, dnsOutbound.WritePacketResponseWithResponseObserver(query, response, observed, metadata.Destination, factory()))
	require.Equal(t, hServedDNSWire(t, response), legacy.wire)
	require.Equal(t, legacy.wire, observed.wire)
}
