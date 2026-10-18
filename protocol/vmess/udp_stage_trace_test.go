package vmess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/udptrace"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func udpStageSelector() udptrace.Selector {
	return udptrace.Selector{Network: N.NetworkUDP, SourcePort: 40123, Destination: netip.MustParseAddrPort("192.0.2.1:3478"), Outbound: "trace-test"}
}

func udpStageManager(t *testing.T) (*udptrace.Manager, string) {
	t.Helper()
	manager, err := udptrace.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	manager.Enable()
	idle, err := manager.Snapshot("")
	if err != nil {
		t.Fatal(err)
	}
	armed, err := manager.Arm(idle.Generation, udpStageSelector())
	if err != nil {
		t.Fatal(err)
	}
	return manager, armed.Generation
}

func udpStageClaim(t *testing.T) (*udptrace.Manager, *udptrace.Trace, string) {
	t.Helper()
	manager, generation := udpStageManager(t)
	trace := manager.TryClaim(udpStageSelector())
	if trace == nil {
		t.Fatal("expected one exact claim")
	}
	return manager, trace, generation
}

func udpStageSnapshot(t *testing.T, manager *udptrace.Manager, generation string) udptrace.Snapshot {
	t.Helper()
	snapshot, err := manager.Snapshot(generation)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func udpStageEvent(t *testing.T, snapshot udptrace.Snapshot, stage udptrace.Stage) udptrace.Event {
	t.Helper()
	var matches []udptrace.Event
	for _, event := range snapshot.Events {
		if event.Stage == stage {
			matches = append(matches, event)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("stage %s count=%d", stage, len(matches))
	}
	return matches[0]
}

func TestUDPStageEntryMatching(t *testing.T) {
	for _, name := range []string{"exact", "mapped", "no-metadata", "tcp", "source-port", "destination", "destination-port", "domain", "tag"} {
		t.Run(name, func(t *testing.T) {
			manager, generation := udpStageManager(t)
			h := &Outbound{
				Adapter:  outbound.NewAdapterWithDialerOptions(C.TypeVMess, "trace-test", []string{N.NetworkUDP}, option.DialerOptions{}),
				udpTrace: manager,
				xudp:     true,
			}
			metadata := adapter.InboundContext{Network: N.NetworkUDP, Source: M.Socksaddr{Port: 40123}}
			destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 3478}
			ctx := context.Background()
			switch name {
			case "mapped":
				destination.Addr = netip.MustParseAddr("::ffff:192.0.2.1")
			case "tcp":
				metadata.Network = N.NetworkTCP
			case "source-port":
				metadata.Source.Port++
			case "destination":
				destination.Addr = netip.MustParseAddr("192.0.2.2")
			case "destination-port":
				destination.Port++
			case "domain":
				destination.Fqdn = "example.invalid"
			case "tag":
				h.Adapter = outbound.NewAdapterWithDialerOptions(C.TypeVMess, "other", []string{N.NetworkUDP}, option.DialerOptions{})
			}
			if name != "no-metadata" {
				ctx = adapter.WithContext(ctx, &metadata)
			}
			trace := h.traceUDPEntry(ctx, destination, false)
			wantClaim := name == "exact" || name == "mapped"
			if (trace != nil) != wantClaim {
				t.Fatalf("claimed=%v want=%v", trace != nil, wantClaim)
			}
			snapshot := udpStageSnapshot(t, manager, generation)
			if !wantClaim && (snapshot.State != udptrace.StateArmed || len(snapshot.Events) != 0) {
				t.Fatal("a nonmatching entry changed the recorder")
			}
		})
	}
}

func TestUDPStageUnsupportedEntry(t *testing.T) {
	for _, name := range []string{"connected", "mux", "encoding", "packetaddr"} {
		t.Run(name, func(t *testing.T) {
			manager, generation := udpStageManager(t)
			h := &Outbound{
				Adapter:  outbound.NewAdapterWithDialerOptions(C.TypeVMess, "trace-test", []string{N.NetworkUDP}, option.DialerOptions{}),
				udpTrace: manager,
				xudp:     true,
			}
			want := udptrace.UnsupportedEncoding
			switch name {
			case "connected":
				want = udptrace.UnsupportedUDPConnect
			case "mux":
				h.multiplexDialer = new(mux.Client)
				want = udptrace.UnsupportedMultiplex
			case "encoding":
				h.xudp = false
			case "packetaddr":
				h.packetAddr = true
			}
			ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{Network: N.NetworkUDP, Source: M.Socksaddr{Port: 40123}})
			if h.traceUDPEntry(ctx, M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 3478}, name == "connected") != nil {
				t.Fatal("unsupported entry received an observer")
			}
			snapshot := udpStageSnapshot(t, manager, generation)
			event := udpStageEvent(t, snapshot, udptrace.StageUnsupported)
			if snapshot.State != udptrace.StateStopped || event.Detail == nil || event.Detail.Unsupported != want {
				t.Fatal("unsupported entry did not retain its bounded reason")
			}
		})
	}
}

func TestUDPStagePrefixWindow(t *testing.T) {
	// Opaque byte-window tests only: no protocol frame or protocol decoder.
	var window udpStagePrefix
	input := []byte("opaque-window-data")
	for _, fragment := range [][]byte{input[:2], input[2:4], input[4:]} {
		tracked, ambiguous := window.begin()
		if !tracked || ambiguous {
			t.Fatal("sequential read was rejected")
		}
		prefix, count, complete, unknown := window.finish(tracked, fragment, true)
		if unknown || count > udptrace.PrefixBytes {
			t.Fatal("invalid prefix bound")
		}
		if complete && !bytes.Equal(prefix[:], input[:udptrace.PrefixBytes]) {
			t.Fatal("prefix bytes changed")
		}
	}
	if tracked, _ := window.begin(); tracked || window.bytes != [udptrace.PrefixBytes]byte{} {
		t.Fatal("completed window retained bytes or accepted more reads")
	}
	var concurrent udpStagePrefix
	first, _ := concurrent.begin()
	second, ambiguous := concurrent.begin()
	if !ambiguous {
		t.Fatal("overlapping reads were not detected")
	}
	for _, tracked := range []bool{second, first} {
		_, count, complete, unknown := concurrent.finish(tracked, input, true)
		if count != 0 || complete || !unknown || concurrent.bytes != [udptrace.PrefixBytes]byte{} {
			t.Fatal("ambiguous window retained a prefix")
		}
	}
}

func TestUDPStageReadTapShortReadAndEOF(t *testing.T) {
	manager, trace, generation := udpStageClaim(t)
	fake := &udpStageFakeConn{readData: []byte("xy")}
	tap := &udpStageReadTap{Conn: fake, trace: trace}
	p := make([]byte, 10)
	if n, err := tap.Read(p); n != 2 || err != nil || string(p[:n]) != "xy" {
		t.Fatal("first read changed")
	}
	fake.readData = nil
	fake.readErr = io.EOF
	if n, err := tap.Read(p); n != 0 || err != io.EOF || fake.calls["Read"] != 2 {
		t.Fatal("EOF was changed or additional reads occurred")
	}
	snapshot := udpStageSnapshot(t, manager, generation)
	if snapshot.Header.State != udptrace.HeaderWaiting || snapshot.Header.CapturedBytes != 2 || snapshot.Header.Decoded != nil {
		t.Fatal("short reads invented a complete header")
	}
	first := udpStageEvent(t, snapshot, udptrace.StageDecodedReadReturn)
	failure := udpStageEvent(t, snapshot, udptrace.StageDecodedReadError)
	if first.Detail == nil || first.Detail.Error != udptrace.ErrorNone || failure.Detail == nil || failure.Detail.Error != udptrace.ErrorEOF {
		t.Fatal("first successful read hid the subsequent lower read error")
	}
	if tap.Upstream() != fake || tap.ReaderReplaceable() || tap.WriterReplaceable() {
		t.Fatal("tap capabilities changed")
	}
}

func TestUDPStageReadTapConcurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, trace, generation := udpStageClaim(t)
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		fake := &udpStageBlockingConn{entered: entered, release: release}
		tap := &udpStageReadTap{Conn: fake, trace: trace}
		var group sync.WaitGroup
		for range 2 {
			group.Go(func() {
				p := make([]byte, 1)
				if n, err := tap.Read(p); n != 1 || err != io.EOF || p[0] != 'x' {
					t.Error("concurrent read result changed")
				}
			})
		}
		synctest.Wait()
		if len(entered) != 2 {
			t.Fatal("observer serialized the underlying reads")
		}
		close(release)
		group.Wait()
		header := udpStageSnapshot(t, manager, generation).Header
		if header.State != udptrace.HeaderUnknownConcurrent || header.Decoded != nil || header.CapturedBytes != 0 {
			t.Fatal("ambiguous fragments were presented as an ordered header")
		}
	})
}

func TestUDPStagePacketMethodsAndCapabilities(t *testing.T) {
	for _, method := range []string{"Read", "Write", "ReadFrom", "WriteTo", "ReadPacket", "WritePacket"} {
		t.Run(method, func(t *testing.T) {
			manager, trace, generation := udpStageClaim(t)
			fake := &udpStageFakeConn{readData: []byte("xy"), readErr: io.EOF, writeErr: io.ErrShortWrite, handshake: true, readDeadlineNeeded: true}
			conn := &udpStagePacketConn{PacketConn: fake, capabilities: fake, trace: trace}
			payload := []byte("opaque")
			address := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 7}
			switch method {
			case "Read":
				n, err := conn.Read(payload)
				if n != 2 || err != io.EOF || string(payload[:n]) != "xy" {
					t.Fatal("Read changed n/data/error")
				}
			case "Write":
				if n, err := conn.Write(payload); n != len(payload)-1 || err != io.ErrShortWrite {
					t.Fatal("Write changed n/error")
				}
			case "ReadFrom":
				fake.address = address
				if n, got, err := conn.ReadFrom(payload); n != 2 || got != address || err != io.EOF {
					t.Fatal("ReadFrom changed n/address/error")
				}
			case "WriteTo":
				if n, err := conn.WriteTo(payload, address); n != len(payload)-1 || err != io.ErrShortWrite || fake.address != address {
					t.Fatal("WriteTo changed n/address/error")
				}
			case "ReadPacket":
				fake.readErr = nil
				buffer := buf.NewSize(32)
				defer buffer.Release()
				fake.destination = M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.3"), Port: 7}
				if got, err := conn.ReadPacket(buffer); got != fake.destination || err != nil || string(buffer.Bytes()) != "xy" {
					t.Fatal("ReadPacket changed destination/buffer/error")
				}
			case "WritePacket":
				buffer := buf.NewSize(32)
				if _, err := buffer.Write(payload); err != nil {
					t.Fatal(err)
				}
				destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.3"), Port: 7}
				if err := conn.WritePacket(buffer, destination); err != io.ErrShortWrite || fake.destination != destination || !bytes.Equal(fake.written, payload) {
					t.Fatal("WritePacket changed destination/data/error")
				}
				snapshot := udpStageSnapshot(t, manager, generation)
				enter := udpStageEvent(t, snapshot, udptrace.StagePacketWriteEnter)
				result := udpStageEvent(t, snapshot, udptrace.StagePacketWriteReturn)
				if enter.Detail == nil || !enter.Detail.HasBytes || enter.Detail.Bytes != len(payload) || result.Detail == nil || result.Detail.HasBytes {
					t.Fatal("consumed buffer was accessed or a write byte count was invented")
				}
			}
			if len(fake.calls) != 1 || fake.calls[method] != 1 {
				t.Fatalf("method was replaced or delegated more than once: %v", fake.calls)
			}
			if conn.Upstream() != fake || conn.ReaderReplaceable() || conn.WriterReplaceable() || !conn.NeedHandshake() || !conn.NeedAdditionalReadDeadline() {
				t.Fatal("packet capabilities changed")
			}
			fake.handshake, fake.readDeadlineNeeded = false, false
			if conn.NeedHandshake() || conn.NeedAdditionalReadDeadline() {
				t.Fatal("packet capabilities were hardcoded")
			}
			if N.CalculateFrontHeadroom(conn) != 7 || N.CalculateRearHeadroom(conn) != 11 {
				t.Fatal("headroom was lost or counted twice")
			}
			fake.lazy = true
			if N.CalculateFrontHeadroom(conn) != N.DefaultHeadroom || N.CalculateRearHeadroom(conn) != N.DefaultHeadroom {
				t.Fatal("lazy headroom was lost")
			}
		})
	}
}

func TestUDPStageClearAndDeadlineTransparency(t *testing.T) {
	manager, trace, generation := udpStageClaim(t)
	fake := &udpStageFakeConn{readData: []byte("x"), closeErr: io.ErrClosedPipe, deadlineErr: errors.New("fake deadline failure"), address: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 4), Port: 9}}
	conn := &udpStagePacketConn{PacketConn: fake, capabilities: fake, trace: trace}
	target := time.Unix(123, 456)
	for _, setter := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if err := setter(target); err != fake.deadlineErr || fake.deadline != target {
			t.Fatal("deadline argument/result changed")
		}
	}
	cleared, err := manager.Clear(generation)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls["Close"] != 0 {
		t.Fatal("Clear closed a business connection")
	}
	before := udpStageSnapshot(t, manager, cleared.Generation)
	if _, err := conn.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != fake.closeErr || fake.calls["Close"] != 1 {
		t.Fatal("business Close was changed")
	}
	after := udpStageSnapshot(t, manager, cleared.Generation)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("old wrapper wrote into a cleared generation")
	}
	if conn.LocalAddr() != fake.address || conn.RemoteAddr() != fake.address {
		t.Fatal("address methods changed")
	}
}

func TestUDPStageDormantAndUnsupportedTypes(t *testing.T) {
	fake := new(udpStageFakeConn)
	if observeXUDPPacketConn(fake, nil) != fake || len(fake.calls) != 0 {
		t.Fatal("dormant observer changed the returned object")
	}
	manager, trace, generation := udpStageClaim(t)
	if observeXUDPPacketConn(fake, trace) != fake || len(fake.calls) != 0 {
		t.Fatal("unsupported type was wrapped or used")
	}
	event := udpStageEvent(t, udpStageSnapshot(t, manager, generation), udptrace.StageUnsupported)
	if event.Detail == nil || event.Detail.Unsupported != udptrace.UnsupportedType {
		t.Fatal("unsupported type was not reported")
	}
}

func TestUDPStageScopedBackend(t *testing.T) {
	manager, trace, generation := udpStageClaim(t)
	ctx := context.WithValue(context.Background(), udpStageContextKey{}, "opaque context")
	innerError := errors.New("nested dial failure must not become the observed return")
	inner := &vmessDialer{dialer: udpStageFakeDialer{dial: func(got context.Context) (net.Conn, error) {
		if got != ctx {
			t.Fatal("nested business context changed")
		}
		return nil, innerError
	}}}
	result := new(udpStageFakeConn)
	outer := &vmessDialer{connectionSetup: newConnectionSetupLimiter(true), dialer: udpStageFakeDialer{dial: func(got context.Context) (net.Conn, error) {
		if got != ctx {
			t.Fatal("observed business context changed")
		}
		if _, err := inner.dialServer(got); err != innerError {
			t.Fatal("nested return changed")
		}
		return result, nil
	}}}
	if conn, err := outer.dialServerWithTrace(ctx, trace); conn != result || err != nil || len(outer.connectionSetup.slots) != 0 {
		t.Fatal("backend result or admission release changed")
	}
	event := udpStageEvent(t, udpStageSnapshot(t, manager, generation), udptrace.StageBackendReturn)
	if event.Detail == nil || event.Detail.Backend != udptrace.BackendTCP || event.Detail.Error != udptrace.ErrorNone {
		t.Fatal("nested unobserved call polluted the scoped backend result")
	}
}

func TestUDPStageAdmissionCancellation(t *testing.T) {
	manager, trace, generation := udpStageClaim(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &vmessDialer{connectionSetup: newConnectionSetupLimiter(true), dialer: udpStageFakeDialer{dial: func(context.Context) (net.Conn, error) {
		t.Fatal("canceled admission invoked backend")
		return nil, context.Canceled
	}}}
	if conn, err := h.dialServerWithTrace(ctx, trace); conn != nil || err != context.Canceled || len(h.connectionSetup.slots) != 0 {
		t.Fatal("canceled admission result changed")
	}
	snapshot := udpStageSnapshot(t, manager, generation)
	event := udpStageEvent(t, snapshot, udptrace.StageAcquireReturn)
	if event.Detail == nil || event.Detail.Error != udptrace.ErrorCanceled {
		t.Fatal("admission failure was not retained")
	}
	for _, event := range snapshot.Events {
		if event.Stage == udptrace.StageBackendEnter || event.Stage == udptrace.StageBackendReturn {
			t.Fatal("failed admission invented a backend event")
		}
	}
}

func TestUDPStageQueuedAdmissionAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, trace, generation := udpStageClaim(t)
		ctx := context.Background()
		limiter := newConnectionSetupLimiter(true)
		for range iosMaxConcurrentConnectionSetups {
			if err := limiter.acquire(ctx); err != nil {
				t.Fatal(err)
			}
		}
		fake := &udpStageFakeConn{readData: []byte("x")}
		h := &vmessDialer{connectionSetup: limiter, dialer: udpStageFakeDialer{dial: func(got context.Context) (net.Conn, error) {
			if got != ctx || got.Err() != nil {
				t.Fatal("observation expiry changed the business context")
			}
			return fake, nil
		}}}
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			if conn, err := h.dialServerWithTrace(ctx, trace); conn != fake || err != nil {
				t.Error("queued backend result changed")
			}
		}()
		synctest.Wait()
		queued := udpStageSnapshot(t, manager, generation)
		udpStageEvent(t, queued, udptrace.StageAcquireEnter)
		for _, event := range queued.Events {
			if event.Stage == udptrace.StageAcquireReturn || event.Stage == udptrace.StageBackendEnter {
				t.Fatal("queue entry was mistaken for admission")
			}
		}
		time.Sleep(udptrace.MaxDuration + time.Second)
		stopped := udpStageSnapshot(t, manager, generation)
		if stopped.State != udptrace.StateStopped || len(limiter.slots) != iosMaxConcurrentConnectionSetups {
			t.Fatal("expiry released a business permit or did not stop observation")
		}
		limiter.release()
		<-finished
		for range iosMaxConcurrentConnectionSetups - 1 {
			limiter.release()
		}
		if !reflect.DeepEqual(stopped, udpStageSnapshot(t, manager, generation)) || fake.calls["Close"] != 0 {
			t.Fatal("late backend completion modified the frozen trace or closed the connection")
		}
		tap := &udpStageReadTap{Conn: fake, trace: trace}
		if n, err := tap.Read(make([]byte, 2)); n != 1 || err != nil || fake.calls["Read"] != 1 {
			t.Fatal("expired read tap changed I/O")
		}
		if !reflect.DeepEqual(stopped, udpStageSnapshot(t, manager, generation)) {
			t.Fatal("expired read tap kept recording")
		}
	})
}

type udpStageContextKey struct{}

type udpStageFakeDialer struct {
	dial func(context.Context) (net.Conn, error)
}

func (d udpStageFakeDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func (d udpStageFakeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unexpected packet dial in an abstract backend test")
}

type udpStageFakeConn struct {
	calls              map[string]int
	readData           []byte
	written            []byte
	readErr            error
	writeErr           error
	closeErr           error
	deadlineErr        error
	address            net.Addr
	destination        M.Socksaddr
	deadline           time.Time
	handshake          bool
	readDeadlineNeeded bool
	lazy               bool
}

func (c *udpStageFakeConn) called(name string) {
	if c.calls == nil {
		c.calls = make(map[string]int)
	}
	c.calls[name]++
}

func (c *udpStageFakeConn) Read(p []byte) (int, error) {
	c.called("Read")
	return copy(p, c.readData), c.readErr
}

func (c *udpStageFakeConn) Write(p []byte) (int, error) {
	c.called("Write")
	c.written = append([]byte(nil), p...)
	return len(p) - 1, c.writeErr
}

func (c *udpStageFakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.called("ReadFrom")
	return copy(p, c.readData), c.address, c.readErr
}

func (c *udpStageFakeConn) WriteTo(p []byte, address net.Addr) (int, error) {
	c.called("WriteTo")
	c.address = address
	c.written = append([]byte(nil), p...)
	return len(p) - 1, c.writeErr
}

func (c *udpStageFakeConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.called("ReadPacket")
	if _, err := buffer.Write(c.readData); err != nil {
		return c.destination, err
	}
	return c.destination, c.readErr
}

func (c *udpStageFakeConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.called("WritePacket")
	c.destination = destination
	c.written = append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	return c.writeErr
}

func (c *udpStageFakeConn) Close() error                     { c.called("Close"); return c.closeErr }
func (c *udpStageFakeConn) LocalAddr() net.Addr              { return c.address }
func (c *udpStageFakeConn) RemoteAddr() net.Addr             { return c.address }
func (c *udpStageFakeConn) NeedHandshake() bool              { return c.handshake }
func (c *udpStageFakeConn) NeedAdditionalReadDeadline() bool { return c.readDeadlineNeeded }
func (c *udpStageFakeConn) FrontHeadroom() int               { return 7 }
func (c *udpStageFakeConn) RearHeadroom() int                { return 11 }
func (c *udpStageFakeConn) LazyHeadroom() bool               { return c.lazy }
func (c *udpStageFakeConn) SetDeadline(t time.Time) error {
	c.called("SetDeadline")
	c.deadline = t
	return c.deadlineErr
}
func (c *udpStageFakeConn) SetReadDeadline(t time.Time) error {
	c.called("SetReadDeadline")
	c.deadline = t
	return c.deadlineErr
}
func (c *udpStageFakeConn) SetWriteDeadline(t time.Time) error {
	c.called("SetWriteDeadline")
	c.deadline = t
	return c.deadlineErr
}

type udpStageBlockingConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *udpStageBlockingConn) Read(p []byte) (int, error) {
	c.entered <- struct{}{}
	<-c.release
	p[0] = 'x'
	return 1, io.EOF
}
