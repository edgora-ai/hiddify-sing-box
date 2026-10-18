package vmess

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestVMessConnectionSetupLimit(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		for _, call := range []string{"tcp", "udp", "packet", "xudp", "packetaddr", "mixed"} {
			t.Run(path+"/"+call, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					release := make(chan struct{})
					releaseAll := sync.OnceFunc(func() { close(release) })
					defer releaseAll()
					var active, peak, calls atomic.Int32
					h := newSetupTestOutbound(t, path, call, true, func(context.Context) (net.Conn, error) {
						current := active.Add(1)
						for previous := peak.Load(); current > previous; previous = peak.Load() {
							if peak.CompareAndSwap(previous, current) {
								break
							}
						}
						calls.Add(1)
						<-release
						active.Add(-1)
						return new(setupTestConn), nil
					})
					const count = 16
					results := make(chan setupTestResult, count)
					for i := range count {
						actualCall := call
						if call == "mixed" {
							actualCall = []string{"tcp", "udp", "packet"}[i%3]
						}
						go setupTestOpen(h, ctx, actualCall, results)
					}
					synctest.Wait()
					if active.Load() != 4 || calls.Load() != 4 || len(results) != 0 {
						t.Fatalf("before release: active=%d calls=%d results=%d", active.Load(), calls.Load(), len(results))
					}
					releaseAll()
					synctest.Wait()
					if peak.Load() != 4 || calls.Load() != count || len(results) != count {
						t.Fatalf("after release: peak=%d calls=%d results=%d", peak.Load(), calls.Load(), len(results))
					}
					// All setups finish before any established connection is closed.
					for range count {
						result := <-results
						if result.err != nil || result.conn == nil {
							t.Fatalf("open: conn=%v err=%v", result.conn, result.err)
						}
						if err := result.conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if len(h.connectionSetup.slots) != 0 {
						t.Fatal("completed setups retained permits")
					}
				})
			})
		}
	}
}

func TestVMessConnectionSetupCanceledContext(t *testing.T) {
	for _, call := range []string{"tcp", "packet"} {
		for _, name := range []string{"pre-canceled", "queued-cancel", "queued-cancel-and-release"} {
			queued := name != "pre-canceled"
			t.Run(call+"/"+name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var calls atomic.Int32
					h := newSetupTestOutbound(t, "transport", call, true, func(context.Context) (net.Conn, error) {
						calls.Add(1)
						return new(setupTestConn), nil
					})
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					occupied := 0
					if queued {
						for range 4 {
							if err := h.connectionSetup.acquire(context.Background()); err != nil {
								t.Fatal(err)
							}
							occupied++
						}
					} else {
						cancel()
					}
					results := make(chan setupTestResult, 1)
					go setupTestOpen(h, ctx, call, results)
					synctest.Wait()
					if queued {
						if len(results) != 0 || calls.Load() != 0 {
							t.Fatal("queued call reached the transport")
						}
						cancel()
						if name == "queued-cancel-and-release" {
							// Cancellation and slot availability may both win the select;
							// neither may allow a canceled call to dial.
							h.connectionSetup.release()
							occupied--
						}
						synctest.Wait()
					}
					result := <-results
					if !errors.Is(result.err, context.Canceled) || result.conn != nil || calls.Load() != 0 {
						t.Fatalf("canceled call: conn=%v err=%v calls=%d", result.conn, result.err, calls.Load())
					}
					if len(h.connectionSetup.slots) != occupied {
						t.Fatal("canceled call retained a permit")
					}
					if occupied == 4 {
						h.connectionSetup.release()
						occupied--
					}
					// A live call can use the free slot after the canceled waiter exits.
					setupTestOpen(h, context.Background(), call, results)
					result = <-results
					if result.err != nil || calls.Load() != 1 {
						t.Fatalf("subsequent call: err=%v calls=%d", result.err, calls.Load())
					}
					if err := result.conn.Close(); err != nil {
						t.Fatal(err)
					}
					for range occupied {
						h.connectionSetup.release()
					}
				})
			})
		}
	}
}

func TestVMessConnectionSetupErrorsRelease(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		for _, call := range []string{"tcp", "packet"} {
			t.Run(path+"/"+call, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					setupErr := errors.New("fake setup failure")
					var calls int
					h := newSetupTestOutbound(t, path, call, true, func(context.Context) (net.Conn, error) {
						calls++
						if calls <= 8 {
							return nil, setupErr
						}
						return new(setupTestConn), nil
					})
					results := make(chan setupTestResult, 1)
					for range 8 {
						setupTestOpen(h, context.Background(), call, results)
						result := <-results
						if result.conn != nil || !errors.Is(result.err, setupErr) || len(h.connectionSetup.slots) != 0 {
							t.Fatalf("failed setup: conn=%v err=%v permits=%d", result.conn, result.err, len(h.connectionSetup.slots))
						}
					}
					setupTestOpen(h, context.Background(), call, results)
					result := <-results
					if result.err != nil || calls != 9 || len(h.connectionSetup.slots) != 0 {
						t.Fatalf("recovery: err=%v calls=%d permits=%d", result.err, calls, len(h.connectionSetup.slots))
					}
					if err := result.conn.Close(); err != nil {
						t.Fatal(err)
					}
				})
			})
		}
	}
}

func TestVMessConnectionSetupClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls, closes atomic.Int32
		h := newSetupTestOutbound(t, "transport", "tcp", true, func(context.Context) (net.Conn, error) {
			calls.Add(1)
			return new(setupTestConn), nil
		})
		finishClose := make(chan struct{})
		releaseClose := sync.OnceFunc(func() { close(finishClose) })
		defer releaseClose()
		closeErr := errors.New("fake transport close failure")
		h.transport.(*setupTestTransport).closeFn = func() error {
			closes.Add(1)
			<-finishClose
			return closeErr
		}
		for range 4 {
			if err := h.connectionSetup.acquire(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := make(chan setupTestResult, 8)
		for range 4 {
			go setupTestOpen(h, ctx, "tcp", results)
			go setupTestOpen(h, ctx, "packet", results)
		}
		synctest.Wait()
		if len(results) != 0 {
			t.Fatal("calls did not queue")
		}
		closeResults := make(chan error, 8)
		go func() { closeResults <- h.Close() }()
		<-h.connectionSetup.done
		// Closing and a newly free slot must not admit a queued call.
		h.connectionSetup.release()
		synctest.Wait()
		// Queue shutdown must not wait for the existing transport's Close.
		if closes.Load() != 1 || len(closeResults) != 0 || len(results) != 8 {
			t.Fatalf("closing: closes=%d completed closes=%d queued results=%d", closes.Load(), len(closeResults), len(results))
		}
		for range 8 {
			result := <-results
			if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
				t.Fatalf("closed waiter: conn=%v err=%v", result.conn, result.err)
			}
		}
		for _, call := range []string{"tcp", "packet"} {
			setupTestOpen(h, context.Background(), call, results)
			result := <-results
			if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
				t.Fatalf("closed with free slot: conn=%v err=%v", result.conn, result.err)
			}
		}
		if calls.Load() != 0 || len(h.connectionSetup.slots) != 3 {
			t.Fatal("closed outbound dialed or retained a new permit")
		}
		// sync.Once mutex waiters are not durably blocked for synctest.Wait.
		// Release transport cleanup before checking concurrent Close callers.
		releaseClose()
		for range 7 {
			go func() { closeResults <- h.Close() }()
		}
		synctest.Wait()
		for range 8 {
			if err := <-closeResults; !errors.Is(err, closeErr) {
				t.Fatalf("Close lost transport error: %v", err)
			}
		}
		if err := h.Close(); !errors.Is(err, closeErr) || closes.Load() != 1 {
			t.Fatalf("repeated Close: err=%v closes=%d", err, closes.Load())
		}
		for range 3 {
			h.connectionSetup.release()
		}
	})
}

func TestVMessConnectionSetupPerOutbound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseAll := sync.OnceFunc(func() { close(release) })
		defer releaseAll()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		results := make(chan setupTestResult, 8)
		for range 2 {
			h := newSetupTestOutbound(t, "transport", "tcp", true, func(context.Context) (net.Conn, error) {
				calls.Add(1)
				<-release
				return new(setupTestConn), nil
			})
			for range 4 {
				go setupTestOpen(h, ctx, "tcp", results)
			}
		}
		synctest.Wait()
		if calls.Load() != 8 {
			t.Fatalf("outbounds shared a limit: calls=%d", calls.Load())
		}
		releaseAll()
		synctest.Wait()
		for range 8 {
			result := <-results
			if result.err != nil {
				t.Fatal(result.err)
			}
			if err := result.conn.Close(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestVMessConnectionSetupDisabled(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		for _, call := range []string{"tcp", "packet"} {
			t.Run(path+"/"+call, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					release := make(chan struct{})
					releaseAll := sync.OnceFunc(func() { close(release) })
					defer releaseAll()
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					var calls atomic.Int32
					h := newSetupTestOutbound(t, path, call, false, func(ctx context.Context) (net.Conn, error) {
						// The disabled path forwards cancellation to the existing backend,
						// without adding new checks or concurrency restrictions.
						if !errors.Is(ctx.Err(), context.Canceled) {
							t.Error("backend did not receive the canceled context")
						}
						calls.Add(1)
						<-release
						return new(setupTestConn), nil
					})
					if h.connectionSetup != nil {
						t.Fatal("disabled limiter was allocated")
					}
					results := make(chan setupTestResult, 8)
					for range 8 {
						go setupTestOpen(h, ctx, call, results)
					}
					synctest.Wait()
					if calls.Load() != 8 || len(results) != 0 {
						t.Fatalf("disabled: calls=%d results=%d", calls.Load(), len(results))
					}
					releaseAll()
					synctest.Wait()
					for range 8 {
						result := <-results
						if result.err != nil {
							t.Fatal(result.err)
						}
						if err := result.conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
				})
			})
		}
	}
}

func TestVMessWebsocketEarlyDataDefault(t *testing.T) {
	var options option.V2RayTransportOptions
	if err := json.Unmarshal([]byte(`{"type":"ws"}`), &options); err != nil {
		t.Fatal(err)
	}
	if options.WebsocketOptions.MaxEarlyData != 0 {
		t.Fatalf("missing max_early_data defaults to %d", options.WebsocketOptions.MaxEarlyData)
	}
}

type setupTestResult struct {
	conn io.Closer
	err  error
}

func setupTestOpen(h *Outbound, ctx context.Context, call string, results chan<- setupTestResult) {
	destination := M.ParseSocksaddr("192.0.2.1:53")
	var result setupTestResult
	if call == "tcp" || call == "udp" {
		conn, err := h.DialContext(ctx, call, destination)
		result.err = err
		if conn != nil {
			result.conn = conn
		}
	} else {
		conn, err := h.ListenPacket(ctx, destination)
		result.err = err
		if conn != nil {
			result.conn = conn
		}
	}
	results <- result
}

func newSetupTestOutbound(t *testing.T, path, call string, enabled bool, dial func(context.Context) (net.Conn, error)) *Outbound {
	t.Helper()
	client, err := vmess.NewClient("00000000-0000-0000-0000-000000000001", "zero", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &Outbound{
		logger:          logger.NOP(),
		client:          client,
		serverAddr:      M.ParseSocksaddr("server.invalid:443"),
		connectionSetup: newConnectionSetupLimiter(enabled),
		packetAddr:      call == "packetaddr",
		xudp:            call == "xudp",
	}
	h.dialer = &setupTestDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if path != "plain" {
			return nil, errors.New("unexpected plain server dial")
		}
		if network != N.NetworkTCP || destination != h.serverAddr {
			t.Errorf("plain server dial: network=%s destination=%s", network, destination)
		}
		return dial(ctx)
	}}
	if path != "plain" {
		h.tlsDialer = &setupTestTLSDialer{Dialer: h.dialer, dial: func(ctx context.Context, destination M.Socksaddr) (tls.Conn, error) {
			if path != "tls" {
				return nil, errors.New("unexpected TLS server dial")
			}
			if destination != h.serverAddr {
				t.Errorf("TLS server dial: destination=%s", destination)
			}
			conn, err := dial(ctx)
			if conn == nil {
				return nil, err
			}
			return &setupTestTLSConn{Conn: conn}, err
		}}
	}
	if path == "transport" {
		h.transport = &setupTestTransport{dial: dial}
	}
	return h
}

type setupTestTransport struct {
	dial    func(context.Context) (net.Conn, error)
	closeFn func() error
}

func (t *setupTestTransport) DialContext(ctx context.Context) (net.Conn, error) {
	return t.dial(ctx)
}

func (t *setupTestTransport) Close() error {
	if t.closeFn != nil {
		return t.closeFn()
	}
	return nil
}

type setupTestDialer struct {
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d *setupTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, destination)
}

func (d *setupTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected underlying ListenPacket")
}

type setupTestTLSDialer struct {
	N.Dialer
	dial func(context.Context, M.Socksaddr) (tls.Conn, error)
}

func (d *setupTestTLSDialer) DialTLSContext(ctx context.Context, destination M.Socksaddr) (tls.Conn, error) {
	return d.dial(ctx, destination)
}

type setupTestTLSConn struct {
	net.Conn
}

func (c *setupTestTLSConn) NetConn() net.Conn { return c.Conn }

func (c *setupTestTLSConn) HandshakeContext(context.Context) error { return nil }

func (c *setupTestTLSConn) ConnectionState() tls.ConnectionState { return tls.ConnectionState{} }

type setupTestConn struct {
	closed atomic.Bool
}

func (c *setupTestConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *setupTestConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *setupTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *setupTestConn) LocalAddr() net.Addr  { return new(net.TCPAddr) }
func (c *setupTestConn) RemoteAddr() net.Addr { return new(net.TCPAddr) }

func (c *setupTestConn) SetDeadline(time.Time) error      { return nil }
func (c *setupTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *setupTestConn) SetWriteDeadline(time.Time) error { return nil }
