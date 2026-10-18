package vmess

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/common/udptrace"
	N "github.com/sagernet/sing/common/network"
)

const iosMaxConcurrentConnectionSetups = 4

type connectionSetupLimiter struct {
	slots     chan struct{}
	done      chan struct{}
	mutex     sync.Mutex
	resetDone chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newConnectionSetupLimiter(enabled bool) *connectionSetupLimiter {
	if !enabled {
		return nil
	}
	return &connectionSetupLimiter{
		slots:     make(chan struct{}, iosMaxConcurrentConnectionSetups),
		done:      make(chan struct{}),
		resetDone: make(chan struct{}),
	}
}

func (l *connectionSetupLimiter) check(ctx context.Context, resetDone <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-l.done:
		return net.ErrClosed
	case <-resetDone:
		return net.ErrClosed
	default:
		return nil
	}
}

func (l *connectionSetupLimiter) acquire(ctx context.Context) error {
	l.mutex.Lock()
	resetDone := l.resetDone
	l.mutex.Unlock()
	if err := l.check(ctx, resetDone); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return net.ErrClosed
	case <-resetDone:
		return net.ErrClosed
	case l.slots <- struct{}{}:
	}
	// Cancellation, Close, or reset may race with an available slot. Serialize
	// admission with reset, and check the captured generation rather than a new one.
	l.mutex.Lock()
	err := l.check(ctx, resetDone)
	l.mutex.Unlock()
	if err != nil {
		l.release()
		return err
	}
	return nil
}

func (l *connectionSetupLimiter) release() {
	<-l.slots
}

// reset invalidates queued setups, not admitted backend calls or their contexts.
// Keep the same slots so admitted calls still count toward the concurrency limit.
func (l *connectionSetupLimiter) reset() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	select {
	case <-l.done:
		return
	default:
	}
	close(l.resetDone)
	l.resetDone = make(chan struct{})
}

func (l *connectionSetupLimiter) close(closeOutbound func() error) error {
	l.closeOnce.Do(func() {
		// Wake queued dials before closing the existing transport and multiplex client.
		l.mutex.Lock()
		close(l.done)
		l.mutex.Unlock()
		l.closeErr = closeOutbound()
	})
	return l.closeErr
}

// dialServer limits only synchronous server setup, not established connections.
// A transport's post-return work, such as a WebSocket early-data upgrade on the
// first write, is outside the permit's lifetime.
func (h *vmessDialer) dialServer(ctx context.Context) (net.Conn, error) {
	return h.dialServerWithTrace(ctx, nil)
}

func (h *vmessDialer) dialServerWithTrace(ctx context.Context, trace *udptrace.Trace) (net.Conn, error) {
	if h.connectionSetup != nil {
		trace.Record(udptrace.StageAcquireEnter, udptrace.Detail{})
		err := h.connectionSetup.acquire(ctx)
		recordUDPResult(trace, udptrace.StageAcquireReturn, err, 0, false)
		if err != nil {
			return nil, err
		}
		defer h.connectionSetup.release()
	}
	kind := udptrace.BackendTCP
	if h.transport != nil {
		kind = udptrace.BackendTransport
	} else if h.tlsDialer != nil {
		kind = udptrace.BackendTLS
	}
	trace.Record(udptrace.StageBackendEnter, udptrace.Detail{Backend: kind})
	var (
		conn net.Conn
		err  error
	)
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if trace.Active() {
		trace.Record(udptrace.StageBackendReturn, udptrace.Detail{Backend: kind, Error: udptrace.ClassifyError(err)})
	}
	return conn, err
}
