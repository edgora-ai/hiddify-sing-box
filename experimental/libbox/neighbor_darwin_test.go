//go:build darwin

package libbox

import "testing"

func TestNeighborSubscriptionLoopCloseUnblocksRead(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	loopReturned := runNeighborTestLoop(t, subscription)
	waitForNeighborTestSignal(t, reader.readStarted, "route read to start")

	subscription.Close()
	waitForNeighborTestSignal(t, loopReturned, "canceled route loop to exit")
	assertNeighborTestClosed(t, subscription, reader)
}

func TestNeighborSubscriptionLoopEOFClosesOnce(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	loopReturned := runNeighborTestLoop(t, subscription)
	waitForNeighborTestSignal(t, reader.readStarted, "route read to start")

	reader.unblock()
	waitForNeighborTestSignal(t, loopReturned, "route loop to exit on EOF")
	assertNeighborTestClosed(t, subscription, reader)

	subscription.Close()
	subscription.Close()
	assertNeighborTestClosed(t, subscription, reader)
}

func TestNeighborSubscriptionLoopConcurrentCloseAndEOF(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	loopReturned := runNeighborTestLoop(t, subscription)
	waitForNeighborTestSignal(t, reader.readStarted, "route read to start")
	start := make(chan struct{})
	eofReleased := make(chan struct{})
	closeReturned := make(chan struct{})
	go func() {
		<-start
		reader.unblock()
		close(eofReleased)
	}()
	go func() {
		<-start
		subscription.Close()
		close(closeReturned)
	}()
	close(start)

	waitForNeighborTestSignal(t, eofReleased, "EOF to be released")
	waitForNeighborTestSignal(t, closeReturned, "concurrent close to return")
	waitForNeighborTestSignal(t, loopReturned, "route loop to exit")
	assertNeighborTestClosed(t, subscription, reader)
}

func TestNeighborSubscriptionInitialCallbackCanClose(t *testing.T) {
	subscription, reader := newNeighborTestSubscription(t)
	callbackCalls := 0
	listener := neighborTestUpdateListener(func(entries NeighborEntryIterator) {
		callbackCalls++
		if subscription.reader != reader {
			t.Error("owned reader was not registered before the initial callback")
		}
		select {
		case <-reader.readStarted:
			t.Error("route read started before the initial callback returned")
		default:
		}
		if entries.HasNext() {
			t.Error("initial neighbor snapshot was not empty")
		}
		subscription.Close()
		subscription.Close()
	})
	startReturned := make(chan struct{})
	go func() {
		subscription.start(listener, nil)
		close(startReturned)
	}()
	waitForNeighborTestSignal(t, startReturned, "reentrant initial callback to return")

	if callbackCalls != 1 {
		t.Fatalf("initial callback called %d times, want 1", callbackCalls)
	}
	select {
	case <-reader.readStarted:
		t.Fatal("canceled subscription started a route read")
	default:
	}
	assertNeighborTestClosed(t, subscription, reader)
}

type neighborTestUpdateListener func(NeighborEntryIterator)

func (listener neighborTestUpdateListener) UpdateNeighborTable(entries NeighborEntryIterator) {
	listener(entries)
}

func runNeighborTestLoop(t *testing.T, subscription *NeighborSubscription) <-chan struct{} {
	t.Helper()
	returned := make(chan struct{})
	listener := neighborTestUpdateListener(func(NeighborEntryIterator) {
		t.Error("unexpected neighbor update from an EOF-only reader")
	})
	go func() {
		defer close(returned)
		subscription.loop(listener, nil)
	}()
	t.Cleanup(func() {
		subscription.Close()
		waitForNeighborTestSignal(t, returned, "route loop cleanup")
	})
	return returned
}
