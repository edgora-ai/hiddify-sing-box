package udptrace

import (
	"context"
	"testing"
)

func TestUDPTracePrivateContextIsolation(t *testing.T) {
	type applicationKey struct{}
	base, cancel := context.WithCancel(context.WithValue(context.Background(), applicationKey{}, "preserved"))
	defer cancel()
	first := testManager(t)
	second := testManager(t)
	firstContext := ContextWithManager(base, first)
	secondContext := ContextWithManager(firstContext, second)
	if ManagerFromContext(base) != nil || ManagerFromContext(firstContext) != first || ManagerFromContext(secondContext) != second {
		t.Fatal("manager context leaked between instances")
	}
	if firstContext.Value(applicationKey{}) != "preserved" || secondContext.Value(applicationKey{}) != "preserved" {
		t.Fatal("manager context replaced unrelated context values")
	}
	if ManagerFromContext(ContextWithManager(firstContext, nil)) != nil || ManagerFromContext(firstContext) != first {
		t.Fatal("nil manager did not shadow the inherited instance independently")
	}
	if ManagerFromContext(nil) != nil || ManagerFromContext(ContextWithManager(nil, first)) != first {
		t.Fatal("nil context handling failed")
	}
	cancel()
	select {
	case <-secondContext.Done():
	default:
		t.Fatal("manager context replaced business cancellation")
	}
	if secondContext.Err() != context.Canceled {
		t.Fatal("manager context replaced business cancellation error")
	}
	first.Enable()
	if snapshotOf(t, first).State != StateIdle || snapshotOf(t, second).State != StateDisabled {
		t.Fatal("instances share lifecycle state")
	}
	trace := claimManager(t, first)
	second.Close()
	if !trace.Active() {
		t.Fatal("closing another instance stopped this trace")
	}
	first.Disable()
	if secondContext.Err() != context.Canceled {
		t.Fatal("diagnostic stop changed business context state")
	}
}

func TestUDPTraceDiagnosticStopDoesNotCancelBusinessContext(t *testing.T) {
	businessContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := testManager(t)
	ctx := ContextWithManager(businessContext, manager)
	claimManager(t, manager)
	manager.Disable()
	manager.Close()
	if ctx.Err() != nil || businessContext.Err() != nil {
		t.Fatal("stopping observation canceled business context")
	}
	select {
	case <-ctx.Done():
		t.Fatal("stopping observation closed business context")
	default:
	}
}
