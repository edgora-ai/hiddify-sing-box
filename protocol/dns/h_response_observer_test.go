package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	coreDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func hResponseMessages() (*mDNS.Msg, *mDNS.Msg) {
	query := new(mDNS.Msg).SetQuestion("observer.example.test.", mDNS.TypeA)
	response := new(mDNS.Msg).SetReply(query)
	response.Answer = []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 3600},
		A:   net.IPv4(203, 0, 113, 17),
	}}
	return query, response
}

func hResponseWire(t *testing.T, message *mDNS.Msg) []byte {
	t.Helper()
	wire, err := message.Pack()
	require.NoError(t, err)
	return wire
}

func hResponseFrame(wire []byte) []byte {
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	return frame
}

func hResponseReceive[T any](t *testing.T, channel <-chan T) T {
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

type hResponseExchange struct {
	query   *mDNS.Msg
	respond func(*mDNS.Msg, error)
}

type hResponseRouter struct {
	adapter.DNSRouter
	requests chan hResponseExchange
}

func (r *hResponseRouter) ExchangeAsync(_ context.Context, message *mDNS.Msg, _ adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	r.requests <- hResponseExchange{message.Copy(), callback}
}

type hResponseStream struct {
	net.Conn
	reader io.Reader
	writes chan []byte
	limit  int
	err    error
	closed atomic.Bool
}

func (c *hResponseStream) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *hResponseStream) Write(p []byte) (int, error) {
	n := len(p)
	if c.limit >= 0 && c.limit < n {
		n = c.limit
	}
	c.writes <- append([]byte(nil), p[:n]...)
	clear(p)
	return n, c.err
}

func (c *hResponseStream) Close() error {
	c.closed.Store(true)
	return nil
}

type hResponsePacket struct {
	wire        []byte
	destination M.Socksaddr
}

type hResponsePacketWrite struct {
	hResponsePacket
	front int
	rear  int
}

type hResponsePacketConn struct {
	N.PacketConn
	reads      chan hResponsePacket
	writes     chan hResponsePacketWrite
	closed     chan struct{}
	closeOnce  sync.Once
	readCalls  atomic.Int32
	cacheCalls atomic.Int32
	cached     []*N.PacketBuffer
	front      int
	rear       int
	writeErr   error
}

func hResponseNewPacketConn() *hResponsePacketConn {
	return &hResponsePacketConn{
		reads: make(chan hResponsePacket, 8), writes: make(chan hResponsePacketWrite, 8),
		closed: make(chan struct{}), front: 17, rear: 19,
	}
}

func (c *hResponsePacketConn) next() (hResponsePacket, error) {
	select {
	case packet := <-c.reads:
		return packet, nil
	case <-c.closed:
		return hResponsePacket{}, net.ErrClosed
	}
}

func (c *hResponsePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readCalls.Add(1)
	packet, err := c.next()
	if err != nil {
		return M.Socksaddr{}, err
	}
	_, err = buffer.Write(packet.wire)
	return packet.destination, err
}

func (c *hResponsePacketConn) ReadCachedPacket() *N.PacketBuffer {
	c.cacheCalls.Add(1)
	if len(c.cached) == 0 {
		return nil
	}
	packet := c.cached[0]
	c.cached = c.cached[1:]
	return packet
}

func (c *hResponsePacketConn) FrontHeadroom() int { return c.front }
func (c *hResponsePacketConn) RearHeadroom() int  { return c.rear }

func (c *hResponsePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	written := hResponsePacketWrite{
		hResponsePacket: hResponsePacket{append([]byte(nil), buffer.Bytes()...), destination},
		front:           buffer.Start(), rear: buffer.FreeLen(),
	}
	// Actually consume both headrooms, then invalidate and release the payload.
	buffer.ExtendHeader(c.front)
	buffer.Extend(c.rear)
	clear(buffer.Bytes())
	buffer.Release()
	c.writes <- written
	return c.writeErr
}

func (c *hResponsePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type hResponseWaiterConn struct {
	*hResponsePacketConn
	initialized atomic.Bool
	waitCalls   atomic.Int32
}

func (c *hResponseWaiterConn) InitializeReadWaiter(N.ReadWaitOptions) bool {
	c.initialized.Store(true)
	return false
}

func (c *hResponseWaiterConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.waitCalls.Add(1)
	packet, err := c.next()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	buffer := buf.NewSize(len(packet.wire))
	copy(buffer.Extend(len(packet.wire)), packet.wire)
	return buffer, packet.destination, nil
}

func hResponsePacketConnection(t *testing.T, waiter bool, factory ResponseHandlerFactory, cached []*N.PacketBuffer, legacy bool) (*hResponsePacketConn, *hResponseWaiterConn, *hResponseRouter, context.CancelFunc, <-chan error) {
	t.Helper()
	base := hResponseNewPacketConn()
	var conn N.PacketConn = base
	var waiting *hResponseWaiterConn
	if waiter {
		waiting = &hResponseWaiterConn{hResponsePacketConn: base}
		conn = waiting
	}
	router := &hResponseRouter{requests: make(chan hResponseExchange, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if legacy {
			done <- NewDNSPacketConnection(ctx, router, conn, cached, adapter.InboundContext{})
		} else {
			done <- NewDNSPacketConnectionWithResponseObserver(ctx, router, conn, cached, adapter.InboundContext{}, factory)
		}
	}()
	t.Cleanup(func() { cancel(); base.Close() })
	return base, waiting, router, cancel, done
}

func TestH_ResponseObserverPrepareBufferOwnership(t *testing.T) {
	for _, mode := range []string{"nil-handler", "nil-replacement", "aliased-replacement", "larger-replacement"} {
		t.Run(mode, func(t *testing.T) {
			original := buf.NewSize(32)
			copy(original.Extend(4), []byte{1, 2, 3, 4})
			var handler ResponseHandler
			want := []byte{1, 2, 3, 4}
			completed := false
			if mode != "nil-handler" {
				handler = func(wire []byte) ([]byte, func(error)) {
					var replacement []byte
					switch mode {
					case "aliased-replacement":
						replacement = wire[1:]
					case "larger-replacement":
						replacement = bytes.Repeat([]byte{5}, 64)
					}
					return replacement, func(err error) { require.NoError(t, err); completed = true }
				}
			}
			prepared, complete := prepareResponseBuffer(original, 7, 11, handler)
			if mode == "nil-handler" || mode == "nil-replacement" {
				require.Same(t, original, prepared)
			} else {
				require.NotSame(t, original, prepared)
				require.Zero(t, original.RawCap(), "original buffer was not released")
				require.Equal(t, 7, prepared.Start())
				require.Equal(t, 11, prepared.FreeLen())
				if mode == "aliased-replacement" {
					want = []byte{2, 3, 4}
				} else {
					want = bytes.Repeat([]byte{5}, 64)
				}
			}
			require.Equal(t, want, prepared.Bytes())
			prepared.Release()
			if complete != nil {
				complete(nil)
			}
			require.Equal(t, mode != "nil-handler", completed)
		})
	}
}

func TestH_ResponseObserverPacketDeliveryAndTruncation(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("packet write failed"), io.ErrShortWrite} {
		for _, replace := range []bool{false, true} {
			t.Run(map[bool]string{false: "original", true: "replacement"}[replace]+"/"+hResponseErrorName(writeErr), func(t *testing.T) {
				query, response := hResponseMessages()
				for range 8 {
					response.Answer = append(response.Answer, &mDNS.TXT{
						Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeTXT, Class: mDNS.ClassINET, Ttl: 3600},
						Txt: []string{string(bytes.Repeat([]byte{'a'}, 200))},
					})
				}
				sink := hResponseNewPacketConn()
				sink.writeErr = writeErr
				var prepared []byte
				calls := 0
				handler := func(wire []byte) ([]byte, func(error)) {
					var delivered mDNS.Msg
					require.NoError(t, delivered.Unpack(wire))
					require.True(t, delivered.Truncated)
					require.LessOrEqual(t, len(wire), 512)
					var replacement []byte
					if replace {
						delivered.Answer[0].Header().Ttl = 300
						delivered.Compress = true
						replacement = hResponseWire(t, &delivered)
						prepared = append([]byte(nil), replacement...)
					} else {
						prepared = append([]byte(nil), wire...)
					}
					return replacement, func(err error) {
						calls++
						require.ErrorIs(t, err, writeErr)
					}
				}
				destination := M.ParseSocksaddr("192.0.2.1:53")
				err := WritePacketResponseWithResponseObserver(query, response, sink, destination, handler)
				require.ErrorIs(t, err, writeErr)
				require.Equal(t, 1, calls)
				written := hResponseReceive(t, sink.writes)
				require.Equal(t, prepared, written.wire)
				require.Equal(t, destination, written.destination)
				require.GreaterOrEqual(t, written.front, sink.front)
				require.GreaterOrEqual(t, written.rear, sink.rear)
			})
		}
	}
}

func hResponseErrorName(err error) string {
	if err == nil {
		return "success"
	}
	return err.Error()
}

func TestH_ResponseObserverStreamWriteCompletion(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		for _, outcome := range []string{"success", "short-write", "error", "partial-error"} {
			t.Run(map[bool]string{false: "original", true: "replacement"}[replacement]+"/"+outcome, func(t *testing.T) {
				_, response := hResponseMessages()
				sink := &hResponseStream{writes: make(chan []byte, 1), limit: -1}
				var wantErr error
				switch outcome {
				case "short-write":
					sink.limit, wantErr = 5, io.ErrShortWrite
				case "error", "partial-error":
					wantErr = errors.New("stream write failed")
					sink.err = wantErr
					if outcome == "partial-error" {
						sink.limit = 5
					}
				}
				var wantWire []byte
				calls := 0
				handler := func(wire []byte) ([]byte, func(error)) {
					require.Equal(t, hResponseWire(t, response), wire, "handler received a TCP length prefix")
					var wireReplacement []byte
					wantWire = append([]byte(nil), wire...)
					if replacement {
						modified := response.Copy()
						modified.Compress = true
						modified.Answer[0].Header().Ttl = 300
						wireReplacement = hResponseWire(t, modified)
						wantWire = wireReplacement
					}
					return wireReplacement, func(err error) { calls++; require.ErrorIs(t, err, wantErr) }
				}
				require.ErrorIs(t, writeStreamResponse(sink, response, handler), wantErr)
				require.Equal(t, 1, calls)
				frame := hResponseReceive(t, sink.writes)
				if sink.limit < 0 {
					require.Equal(t, len(wantWire), int(binary.BigEndian.Uint16(frame)))
					require.Equal(t, hResponseFrame(wantWire), frame)
				} else {
					require.Equal(t, hResponseFrame(wantWire)[:sink.limit], frame)
				}
			})
		}
	}
}

func TestH_ResponseObserverPrecompressedStreamWire(t *testing.T) {
	_, response := hResponseMessages()
	response.Compress = true
	expected := hResponseWire(t, response)
	for _, observe := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "observer"}[observe], func(t *testing.T) {
			sink := &hResponseStream{writes: make(chan []byte, 1), limit: -1}
			var handler ResponseHandler
			if observe {
				handler = func(wire []byte) ([]byte, func(error)) {
					require.Equal(t, expected, wire, "PackBuffer may return separately allocated scratch storage")
					return nil, nil
				}
			}
			require.NoError(t, writeStreamResponse(sink, response, handler))
			require.Equal(t, hResponseFrame(expected), hResponseReceive(t, sink.writes))
		})
	}
}

func TestH_ResponseObserverStreamOversizeAndPackFailure(t *testing.T) {
	_, response := hResponseMessages()
	sink := &hResponseStream{writes: make(chan []byte, 1), limit: -1}
	calls := 0
	handler := func([]byte) ([]byte, func(error)) {
		return make([]byte, mDNS.MaxMsgSize+1), func(err error) { calls++; require.ErrorIs(t, err, mDNS.ErrBuf) }
	}
	require.ErrorIs(t, writeStreamResponse(sink, response, handler), mDNS.ErrBuf)
	require.Equal(t, 1, calls)
	require.Empty(t, sink.writes)
	response.Rcode = 1 << 13
	require.Error(t, writeStreamResponse(sink, response, func([]byte) ([]byte, func(error)) {
		t.Fatal("observer ran before DNS packing succeeded")
		return nil, nil
	}))
	require.Empty(t, sink.writes)
}

func TestH_ResponseObserverDefaultBytes(t *testing.T) {
	query, response := hResponseMessages()
	response.SetEdns0(1232, true)
	for _, mode := range []string{"legacy", "nil-factory", "nil-handler"} {
		t.Run("tcp/"+mode, func(t *testing.T) {
			conn := &hResponseStream{reader: bytes.NewReader(hResponseFrame(hResponseWire(t, query))), writes: make(chan []byte, 1), limit: -1}
			router := &hResponseRouter{requests: make(chan hResponseExchange, 1)}
			var factory ResponseHandlerFactory
			if mode == "nil-handler" {
				factory = func() ResponseHandler { return nil }
			}
			var err error
			if mode == "legacy" {
				err = HandleStreamDNSRequest(context.Background(), router, conn, adapter.InboundContext{})
			} else {
				err = HandleStreamDNSRequestWithResponseObserver(context.Background(), router, conn, adapter.InboundContext{}, factory)
			}
			require.NoError(t, err)
			hResponseReceive(t, router.requests).respond(response.Copy(), nil)
			require.Equal(t, hResponseFrame(hResponseWire(t, response)), hResponseReceive(t, conn.writes))
		})
		for _, waiter := range []bool{false, true} {
			t.Run("udp/"+mode+map[bool]string{false: "/ordinary", true: "/read-waiter"}[waiter], func(t *testing.T) {
				var factory ResponseHandlerFactory
				if mode == "nil-handler" {
					factory = func() ResponseHandler { return nil }
				}
				conn, _, router, cancel, done := hResponsePacketConnection(t, waiter, factory, nil, mode == "legacy")
				destination := M.ParseSocksaddr("192.0.2.1:53")
				conn.reads <- hResponsePacket{hResponseWire(t, query), destination}
				hResponseReceive(t, router.requests).respond(response.Copy(), nil)
				written := hResponseReceive(t, conn.writes)
				baseline, err := coreDNS.TruncateDNSMessage(query, response, conn.front, conn.rear)
				require.NoError(t, err)
				require.Equal(t, baseline.Bytes(), written.wire)
				baseline.Release()
				require.Equal(t, destination, written.destination)
				cancel()
				require.ErrorIs(t, hResponseReceive(t, done), context.Canceled)
			})
		}
	}
}

func TestH_ResponseObserverPerQueryCapture(t *testing.T) {
	for _, transport := range []string{"tcp", "udp", "udp-read-waiter"} {
		t.Run(transport, func(t *testing.T) {
			var generation, calls atomic.Int32
			completed := make(chan int32, 8)
			factory := func() ResponseHandler {
				calls.Add(1)
				captured := generation.Load()
				if captured == 0 {
					return nil
				}
				return func([]byte) ([]byte, func(error)) {
					return nil, func(err error) { require.NoError(t, err); completed <- captured }
				}
			}
			query, _ := hResponseMessages()
			var submit func() hResponseExchange
			var written func()
			if transport == "tcp" {
				reader := new(bytes.Buffer)
				conn := &hResponseStream{reader: reader, writes: make(chan []byte, 8), limit: -1}
				router := &hResponseRouter{requests: make(chan hResponseExchange, 8)}
				submit = func() hResponseExchange {
					reader.Write(hResponseFrame(hResponseWire(t, query)))
					require.NoError(t, HandleStreamDNSRequestWithResponseObserver(context.Background(), router, conn, adapter.InboundContext{}, factory))
					return hResponseReceive(t, router.requests)
				}
				written = func() { hResponseReceive(t, conn.writes) }
			} else {
				conn, waiting, router, cancel, done := hResponsePacketConnection(t, transport == "udp-read-waiter", factory, nil, false)
				submit = func() hResponseExchange {
					conn.reads <- hResponsePacket{hResponseWire(t, query), M.ParseSocksaddr("192.0.2.1:53")}
					return hResponseReceive(t, router.requests)
				}
				written = func() { hResponseReceive(t, conn.writes) }
				t.Cleanup(func() {
					cancel()
					require.ErrorIs(t, hResponseReceive(t, done), context.Canceled)
					if waiting != nil {
						require.True(t, waiting.initialized.Load())
						require.Positive(t, waiting.waitCalls.Load())
						require.Zero(t, conn.readCalls.Load())
					} else {
						require.Positive(t, conn.readCalls.Load())
					}
				})
			}
			generation.Store(1)
			old := submit()
			generation.Store(2)
			current := submit()
			generation.Store(3)
			for index, exchange := range []hResponseExchange{old, current} {
				exchange.respond(new(mDNS.Msg).SetReply(exchange.query), nil)
				written()
				require.Equal(t, int32(index+1), hResponseReceive(t, completed))
			}
			generation.Store(0)
			disabled := submit()
			generation.Store(4)
			enabled := submit()
			generation.Store(5)
			disabled.respond(new(mDNS.Msg).SetReply(disabled.query), nil)
			written()
			enabled.respond(new(mDNS.Msg).SetReply(enabled.query), nil)
			written()
			require.Equal(t, int32(4), hResponseReceive(t, completed))
			require.Equal(t, int32(4), calls.Load(), "factory must run at parse time, once per query")
			require.Empty(t, completed)
		})
	}
}

type hResponseCounterConn struct {
	*hResponsePacketConn
	reader N.PacketReader
	bytes  atomic.Int64
}

func (c *hResponseCounterConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	return c.reader, []N.CountFunc{func(n int64) { c.bytes.Add(n) }}
}

func TestH_ResponseObserverCachedPacketsAndReadWaiter(t *testing.T) {
	for _, waiter := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "read-waiter"}[waiter], func(t *testing.T) {
			query, response := hResponseMessages()
			wire := hResponseWire(t, query)
			newPacket := func() *N.PacketBuffer {
				packet := N.NewPacketBuffer()
				packet.Buffer = buf.NewSize(len(wire))
				copy(packet.Buffer.Extend(len(wire)), wire)
				packet.Destination = packetDestination()
				return packet
			}
			explicit, discovered := newPacket(), newPacket()
			queryBuffers := []*buf.Buffer{explicit.Buffer, discovered.Buffer}
			base := hResponseNewPacketConn()
			base.cached = []*N.PacketBuffer{discovered}
			var reader N.PacketReader = base
			var waiting *hResponseWaiterConn
			if waiter {
				waiting = &hResponseWaiterConn{hResponsePacketConn: base}
				reader = waiting
			}
			conn := &hResponseCounterConn{hResponsePacketConn: base, reader: reader}
			router := &hResponseRouter{requests: make(chan hResponseExchange, 3)}
			var calls atomic.Int32
			factory := func() ResponseHandler { calls.Add(1); return nil }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			t.Cleanup(func() { cancel(); base.Close() })
			go func() {
				done <- NewDNSPacketConnectionWithResponseObserver(ctx, router, conn, []*N.PacketBuffer{explicit}, adapter.InboundContext{}, factory)
			}()
			for range 2 {
				hResponseReceive(t, router.requests).respond(response.Copy(), nil)
				require.Equal(t, packetDestination(), hResponseReceive(t, base.writes).destination)
			}
			for _, buffer := range queryBuffers {
				require.Zero(t, buffer.RawCap(), "cached query buffer was not released")
			}
			base.reads <- hResponsePacket{wire, packetDestination()}
			hResponseReceive(t, router.requests).respond(response.Copy(), nil)
			hResponseReceive(t, base.writes)
			require.Equal(t, int32(3), calls.Load())
			require.Equal(t, int64(3*len(wire)), conn.bytes.Load(), "cached and live read counters must survive")
			require.GreaterOrEqual(t, base.cacheCalls.Load(), int32(2))
			cancel()
			require.ErrorIs(t, hResponseReceive(t, done), context.Canceled)
			if waiting != nil {
				require.True(t, waiting.initialized.Load())
				require.Zero(t, base.readCalls.Load())
			}
		})
	}
}

func packetDestination() M.Socksaddr { return M.ParseSocksaddr("192.0.2.1:53") }

func TestH_ResponseObserverInvalidQueryDoesNotCapture(t *testing.T) {
	for _, transport := range []string{"tcp", "udp", "udp-read-waiter"} {
		t.Run(transport, func(t *testing.T) {
			factory := func() ResponseHandler { t.Error("factory ran for an invalid query"); return nil }
			invalid := []byte{1, 2, 3}
			if transport == "tcp" {
				for _, frame := range [][]byte{hResponseFrame(invalid), {0, 0}, {0, 10, 1}} {
					conn := &hResponseStream{reader: bytes.NewReader(frame)}
					require.Error(t, HandleStreamDNSRequestWithResponseObserver(context.Background(), &hResponseRouter{}, conn, adapter.InboundContext{}, factory))
				}
			} else {
				conn, _, router, _, done := hResponsePacketConnection(t, transport == "udp-read-waiter", factory, nil, false)
				conn.reads <- hResponsePacket{invalid, packetDestination()}
				require.Error(t, hResponseReceive(t, done))
				require.Empty(t, router.requests)
			}
		})
	}
}
