package libbox

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNeighborSubscriptionCloseUnblocksRead(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	readReturned := make(chan struct{})
	var readErr error
	go func() {
		defer close(readReturned)
		_, readErr = reader.Read(make([]byte, 1))
	}()
	waitForNeighborTestSignal(t, reader.readStarted, "read to start")

	subscription.Close()
	waitForNeighborTestSignal(t, readReturned, "close to unblock read")
	if readErr != io.ErrClosedPipe {
		t.Fatalf("read returned %v, want closed-reader error", readErr)
	}
	subscription.Close()
	assertNeighborTestClosed(t, subscription, reader)
}

func TestNeighborSubscriptionConcurrentClose(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	const callers = 32
	start := make(chan struct{})
	var callersDone sync.WaitGroup
	callersDone.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer callersDone.Done()
			<-start
			subscription.Close()
		}()
	}
	returned := make(chan struct{})
	go func() {
		callersDone.Wait()
		close(returned)
	}()
	close(start)
	waitForNeighborTestSignal(t, returned, "concurrent closes to return")

	subscription.Close()
	assertNeighborTestClosed(t, subscription, reader)
}

func TestNeighborSubscriptionCloseWithoutReader(t *testing.T) {
	// Linux subscriptions do not register an owned reader here.
	subscription := &NeighborSubscription{done: make(chan struct{})}
	subscription.Close()
	subscription.Close()
	select {
	case <-subscription.done:
	default:
		t.Fatal("subscription was not canceled")
	}
}

// The fake read blocks until Close or a simulated EOF; it never opens an OS resource.
// Count every Close invocation, independently of the channel's one-time release.
type neighborTestReadCloser struct {
	readStarted chan struct{}
	closed      chan struct{}
	eof         chan struct{}
	readOnce    sync.Once
	eofOnce     sync.Once
	closeCalls  atomic.Int32
}

func (r *neighborTestReadCloser) Read(_ []byte) (int, error) {
	r.readOnce.Do(func() { close(r.readStarted) })
	select {
	case <-r.closed:
		return 0, io.ErrClosedPipe
	case <-r.eof:
		return 0, io.EOF
	}
}

func (r *neighborTestReadCloser) Close() error {
	if r.closeCalls.Add(1) == 1 {
		close(r.closed)
	}
	return nil
}

func (r *neighborTestReadCloser) unblock() {
	r.eofOnce.Do(func() { close(r.eof) })
}

func newNeighborTestSubscription(t *testing.T) (*NeighborSubscription, *neighborTestReadCloser) {
	t.Helper()
	reader := &neighborTestReadCloser{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
		eof:         make(chan struct{}),
	}
	subscription := &NeighborSubscription{
		done:   make(chan struct{}),
		reader: reader,
	}
	t.Cleanup(func() {
		reader.unblock()
		subscription.Close()
	})
	return subscription, reader
}

func waitForNeighborTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func assertNeighborTestClosed(t *testing.T, subscription *NeighborSubscription, reader *neighborTestReadCloser) {
	t.Helper()
	select {
	case <-subscription.done:
	default:
		t.Fatal("subscription was not canceled")
	}
	if calls := reader.closeCalls.Load(); calls != 1 {
		t.Fatalf("owned reader closed %d times, want 1", calls)
	}
}
