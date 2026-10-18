package vmess

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestVMessConnectionSetupInterfaceUpdated(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		for _, call := range []string{"tcp", "udp", "packet", "xudp", "packetaddr", "mixed"} {
			for _, timing := range []string{"queued", "reset-and-free-slot"} {
				t.Run(path+"/"+call+"/"+timing, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						const admitted, queued = 4, 128
						ctx, cancel := context.WithCancel(context.Background())
						release := make(chan struct{})
						releaseBackend := sync.OnceFunc(func() { close(release) })
						resume := make(chan struct{})
						resumeWaiters := sync.OnceFunc(func() { close(resume) })
						defer func() {
							cancel()
							resumeWaiters()
							releaseBackend()
						}()
						var calls, active, peak atomic.Int32
						contexts := make(chan context.Context, admitted+queued+admitted)
						h := newSetupTestOutbound(t, path, call, true, func(ctx context.Context) (net.Conn, error) {
							calls.Add(1)
							current := active.Add(1)
							for previous := peak.Load(); current > previous; previous = peak.Load() {
								if peak.CompareAndSwap(previous, current) {
									break
								}
							}
							contexts <- ctx
							<-release
							active.Add(-1)
							return new(setupTestConn), nil
						})
						admittedResults := make(chan setupTestResult, admitted)
						for i := range admitted {
							go setupTestOpen(h, ctx, setupResetCall(call, i), admittedResults)
						}
						synctest.Wait()
						if calls.Load() != admitted || active.Load() != admitted || len(admittedResults) != 0 {
							t.Fatalf("initial setups: calls=%d active=%d results=%d", calls.Load(), active.Load(), len(admittedResults))
						}
						waiterResults := make(chan setupTestResult, queued)
						ready := make(chan struct{}, queued)
						for i := range queued {
							var waiterContext context.Context = ctx
							if timing == "reset-and-free-slot" {
								waiterContext = &setupResetSelectContext{Context: ctx, ready: ready, resume: resume}
							}
							go setupTestOpen(h, waiterContext, setupResetCall(call, i), waiterResults)
						}
						synctest.Wait()
						if calls.Load() != admitted || len(waiterResults) != 0 || len(h.connectionSetup.slots) != admitted {
							t.Fatalf("queued setups: calls=%d results=%d permits=%d", calls.Load(), len(waiterResults), len(h.connectionSetup.slots))
						}
						if timing == "reset-and-free-slot" && len(ready) != queued {
							t.Fatalf("waiters did not reach select: ready=%d", len(ready))
						}
						h.InterfaceUpdated(context.Background())
						if timing == "reset-and-free-slot" {
							// Keep old-generation callers immediately before their select
							// until both reset and slot availability are observable.
							releaseBackend()
							synctest.Wait()
							if len(admittedResults) != admitted || len(h.connectionSetup.slots) != 0 {
								t.Fatal("admitted setups did not release their permits")
							}
							resumeWaiters()
						}
						synctest.Wait()
						if len(waiterResults) != queued || calls.Load() != admitted {
							t.Fatalf("reset did not reject old queue: results=%d want=%d backend calls=%d want=%d", len(waiterResults), queued, calls.Load(), admitted)
						}
						setupResetExpectClosed(t, waiterResults, queued)
						if timing == "queued" && (active.Load() != admitted || len(admittedResults) != 0 || len(h.connectionSetup.slots) != admitted) {
							t.Fatal("reset changed already-admitted setup lifetime or permits")
						}
						freshResults := make(chan setupTestResult, admitted)
						for i := range admitted {
							go setupTestOpen(h, ctx, setupResetCall(call, i), freshResults)
						}
						synctest.Wait()
						if timing == "queued" && (len(freshResults) != 0 || calls.Load() != admitted) {
							t.Fatal("new generation bypassed permits held by admitted setups")
						}
						releaseBackend()
						synctest.Wait()
						if len(admittedResults) != admitted || len(freshResults) != admitted || calls.Load() != 2*admitted || peak.Load() != admitted || len(h.connectionSetup.slots) != 0 {
							t.Fatalf("new generation: old results=%d fresh results=%d calls=%d peak=%d permits=%d", len(admittedResults), len(freshResults), calls.Load(), peak.Load(), len(h.connectionSetup.slots))
						}
						// Neither reset nor returning a connection may cancel backend
						// contexts that a transport can retain for established streams.
						for range 2 * admitted {
							backendContext := <-contexts
							if backendContext.Err() != nil || backendContext.Done() != ctx.Done() {
								t.Fatal("backend context was canceled or replaced")
							}
						}
						setupResetExpectSuccess(t, admittedResults, admitted)
						setupResetExpectSuccess(t, freshResults, admitted)
					})
				})
			}
		}
	}
}

func TestVMessConnectionSetupInterfaceUpdatedBeforeTransportClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		h := newSetupTestOutbound(t, "transport", "mixed", true, func(context.Context) (net.Conn, error) {
			calls.Add(1)
			return new(setupTestConn), nil
		})
		for range 4 {
			if err := h.connectionSetup.acquire(ctx); err != nil {
				t.Fatal(err)
			}
		}
		results := make(chan setupTestResult, 128)
		for i := range 128 {
			go setupTestOpen(h, ctx, setupResetCall("mixed", i), results)
		}
		synctest.Wait()
		closeStarted := make(chan struct{})
		finishClose := make(chan struct{})
		releaseClose := sync.OnceFunc(func() { close(finishClose) })
		defer releaseClose()
		h.transport.(*setupTestTransport).closeFn = func() error {
			close(closeStarted)
			<-finishClose
			return nil
		}
		updated := make(chan struct{})
		go func() {
			h.InterfaceUpdated(context.Background())
			close(updated)
		}()
		<-closeStarted
		synctest.Wait()
		select {
		case <-updated:
			t.Fatal("InterfaceUpdated returned before transport cleanup finished")
		default:
		}
		if len(results) != 128 || calls.Load() != 0 {
			t.Fatalf("queue shutdown waited for transport cleanup: results=%d backend calls=%d", len(results), calls.Load())
		}
		setupResetExpectClosed(t, results, 128)
		releaseClose()
		<-updated
		for range 4 {
			h.connectionSetup.release()
		}
	})
}

func TestVMessConnectionSetupInterfaceUpdatedClose(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var calls, closes atomic.Int32
				h := newSetupTestOutbound(t, path, "mixed", true, func(context.Context) (net.Conn, error) {
					calls.Add(1)
					return new(setupTestConn), nil
				})
				closeErr := errors.New("fake transport close failure during reset")
				if path == "transport" {
					h.transport.(*setupTestTransport).closeFn = func() error {
						closes.Add(1)
						return closeErr
					}
				}
				for range 4 {
					if err := h.connectionSetup.acquire(ctx); err != nil {
						t.Fatal(err)
					}
				}
				results := make(chan setupTestResult, 128)
				for i := range 128 {
					go setupTestOpen(h, ctx, setupResetCall("mixed", i), results)
				}
				synctest.Wait()
				start := make(chan struct{})
				closed := make(chan error, 8)
				updated := make(chan struct{}, 16)
				for range 8 {
					go func() { <-start; closed <- h.Close() }()
				}
				for range 16 {
					go func() { <-start; h.InterfaceUpdated(context.Background()); updated <- struct{}{} }()
				}
				close(start)
				synctest.Wait()
				if len(closed) != 8 || len(updated) != 16 || len(results) != 128 || calls.Load() != 0 {
					t.Fatalf("concurrent Close/reset: closes=%d updates=%d waiters=%d backend calls=%d", len(closed), len(updated), len(results), calls.Load())
				}
				setupResetExpectClosed(t, results, 128)
				for range 8 {
					err := <-closed
					if path == "transport" && !errors.Is(err, closeErr) || path != "transport" && err != nil {
						t.Fatalf("Close lost cleanup result: %v", err)
					}
				}
				if path == "transport" && closes.Load() != 17 {
					t.Fatalf("cleanup changed: transport closes=%d want=17", closes.Load())
				}
				for range 4 {
					h.connectionSetup.release()
				}
				for i, call := range []string{"tcp", "udp", "packet", "xudp", "packetaddr"} {
					h.InterfaceUpdated(context.Background())
					setupTestOpen(h, ctx, setupResetCall(call, i), results)
					setupResetExpectClosed(t, results, 1)
				}
				if calls.Load() != 0 || len(h.connectionSetup.slots) != 0 {
					t.Fatal("reset reopened a closed outbound or leaked permits")
				}
			})
		})
	}
}

func TestVMessConnectionSetupInterfaceUpdatedDisabled(t *testing.T) {
	for _, path := range []string{"transport", "tls", "plain"} {
		for _, call := range []string{"tcp", "udp", "packet", "xudp", "packetaddr", "mixed"} {
			t.Run(path+"/"+call, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					release := make(chan struct{})
					releaseBackend := sync.OnceFunc(func() { close(release) })
					defer releaseBackend()
					var calls, closes atomic.Int32
					h := newSetupTestOutbound(t, path, call, false, func(backendContext context.Context) (net.Conn, error) {
						if backendContext.Done() != ctx.Done() || backendContext.Err() != nil {
							t.Error("disabled path changed the backend context")
						}
						calls.Add(1)
						<-release
						return new(setupTestConn), nil
					})
					if path == "transport" {
						h.transport.(*setupTestTransport).closeFn = func() error { closes.Add(1); return nil }
					}
					results := make(chan setupTestResult, 8)
					for i := range 8 {
						go setupTestOpen(h, ctx, setupResetCall(call, i), results)
					}
					synctest.Wait()
					h.InterfaceUpdated(context.Background())
					synctest.Wait()
					if h.connectionSetup != nil || calls.Load() != 8 || len(results) != 0 {
						t.Fatalf("disabled reset: limiter=%v calls=%d results=%d", h.connectionSetup, calls.Load(), len(results))
					}
					if path == "transport" && closes.Load() != 1 || path != "transport" && closes.Load() != 0 {
						t.Fatalf("disabled cleanup changed: closes=%d", closes.Load())
					}
					releaseBackend()
					synctest.Wait()
					setupResetExpectSuccess(t, results, 8)
					setupTestOpen(h, ctx, setupResetCall(call, 0), results)
					setupResetExpectSuccess(t, results, 1)
					if calls.Load() != 9 || h.connectionSetup != nil {
						t.Fatal("disabled outbound did not remain usable")
					}
				})
			})
		}
	}
}

func setupResetCall(call string, index int) string {
	if call == "mixed" {
		return []string{"tcp", "udp", "packet"}[index%3]
	}
	return call
}

func setupResetExpectClosed(t *testing.T, results <-chan setupTestResult, count int) {
	t.Helper()
	for range count {
		result := <-results
		if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("old-generation call: conn=%v err=%v", result.conn, result.err)
		}
	}
}

func setupResetExpectSuccess(t *testing.T, results <-chan setupTestResult, count int) {
	t.Helper()
	for range count {
		result := <-results
		if result.err != nil || result.conn == nil {
			t.Fatalf("open: conn=%v err=%v", result.conn, result.err)
		}
		if err := result.conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// Done pauses select-operand evaluation after acquire has captured a generation.
// Releasing it after reset and permit release exercises both ready select cases.
// No production hook or new limiter method is needed by this regression test.
type setupResetSelectContext struct {
	context.Context
	once   sync.Once
	ready  chan<- struct{}
	resume <-chan struct{}
}

func (c *setupResetSelectContext) Done() <-chan struct{} {
	c.once.Do(func() {
		c.ready <- struct{}{}
		<-c.resume
	})
	return c.Context.Done()
}
