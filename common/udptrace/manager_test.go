package udptrace

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSelector() Selector {
	return Selector{
		Network:     "udp",
		SourcePort:  32123,
		Destination: netip.MustParseAddrPort("192.0.2.7:3478"),
		Outbound:    "private-outbound-sentinel",
	}
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	manager, err := NewManager()
	if err != nil {
		t.Fatal("create manager:", err)
	}
	t.Cleanup(manager.Close)
	return manager
}

func snapshotOf(t *testing.T, manager *Manager) Snapshot {
	t.Helper()
	snapshot, err := manager.Snapshot("")
	if err != nil {
		t.Fatal("snapshot:", err)
	}
	return snapshot
}

func armManager(t *testing.T, manager *Manager) Snapshot {
	t.Helper()
	manager.Enable()
	snapshot, err := manager.Arm(snapshotOf(t, manager).Generation, testSelector())
	if err != nil {
		t.Fatal("arm:", err)
	}
	return snapshot
}

func claimManager(t *testing.T, manager *Manager) *Trace {
	t.Helper()
	armManager(t, manager)
	trace := manager.TryClaim(testSelector())
	if trace == nil {
		t.Fatal("matching flow was not claimed")
	}
	return trace
}

func TestUDPTraceDefaultsAndGenerations(t *testing.T) {
	manager := testManager(t)
	initial := snapshotOf(t, manager)
	if initial.State != StateDisabled || initial.Generation == "" || initial.Claimed ||
		initial.RemainingMS != 0 || len(initial.Events) != 0 || initial.Header.State != HeaderWaiting {
		t.Fatalf("invalid initial snapshot: %+v", initial)
	}
	if initial.Budget != (Budget{MaxDuration.Milliseconds(), 1, MaxEvents, PrefixBytes, MaxResponseBytes}) {
		t.Fatalf("unexpected fixed budget: %+v", initial.Budget)
	}
	if manager.TryClaim(testSelector()) != nil {
		t.Fatal("disabled manager claimed a flow")
	}
	if _, err := manager.Arm(initial.Generation, testSelector()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled arm error: %v", err)
	}
	manager.Enable()
	idle := snapshotOf(t, manager)
	if idle.State != StateIdle || idle.Generation != initial.Generation || manager.TryClaim(testSelector()) != nil {
		t.Fatal("enable armed or changed the idle generation")
	}
	for _, generation := range []string{"", "stale"} {
		if _, err := manager.Arm(generation, testSelector()); !errors.Is(err, ErrGeneration) {
			t.Fatalf("arm accepted missing/stale generation: %v", err)
		}
		if _, err := manager.Clear(generation); !errors.Is(err, ErrGeneration) {
			t.Fatalf("clear accepted missing/stale generation: %v", err)
		}
	}
	invalid := testSelector()
	invalid.SourcePort = 0
	if _, err := manager.Arm(idle.Generation, invalid); !errors.Is(err, ErrInvalidSelector) {
		t.Fatalf("invalid selector error: %v", err)
	}
	if snapshotOf(t, manager).Generation != idle.Generation {
		t.Fatal("failed arm advanced generation")
	}
	armed, err := manager.Arm(idle.Generation, testSelector())
	if err != nil || armed.State != StateArmed || armed.Generation == idle.Generation ||
		armed.RemainingMS <= 0 || armed.RemainingMS > MaxDuration.Milliseconds() {
		t.Fatalf("invalid armed snapshot: %+v, %v", armed, err)
	}
	manager.mu.Lock()
	fixedWindow := manager.timer != nil && manager.deadline.Sub(manager.armedAt) == MaxDuration
	manager.mu.Unlock()
	if !fixedWindow {
		t.Fatal("arm did not store the exact fixed observation window")
	}
	if _, err := manager.Snapshot(idle.Generation); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale snapshot error: %v", err)
	}
	if _, err := manager.Arm(armed.Generation, testSelector()); !errors.Is(err, ErrConflict) {
		t.Fatalf("arm overwrote observation: %v", err)
	}
	other := testManager(t)
	other.Enable()
	otherGeneration := snapshotOf(t, other).Generation
	if otherGeneration == idle.Generation || otherGeneration == armed.Generation {
		t.Fatal("instances reused a generation namespace")
	}
	if _, err := other.Clear(armed.Generation); !errors.Is(err, ErrGeneration) {
		t.Fatalf("another instance accepted generation: %v", err)
	}
}

func TestUDPTraceExactClaimAndMappedIPv4(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*Selector)
	}{
		{"network", func(s *Selector) { s.Network = "tcp" }},
		{"missing network", func(s *Selector) { s.Network = "" }},
		{"source", func(s *Selector) { s.SourcePort++ }},
		{"missing source", func(s *Selector) { s.SourcePort = 0 }},
		{"address", func(s *Selector) { s.Destination = netip.MustParseAddrPort("192.0.2.8:3478") }},
		{"port", func(s *Selector) { s.Destination = netip.MustParseAddrPort("192.0.2.7:3479") }},
		{"missing destination", func(s *Selector) { s.Destination = netip.AddrPort{} }},
		{"outbound", func(s *Selector) { s.Outbound += "-other" }},
		{"missing outbound", func(s *Selector) { s.Outbound = "" }},
	}
	manager := testManager(t)
	armManager(t, manager)
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			selector := testSelector()
			mutation.change(&selector)
			if manager.TryClaim(selector) != nil {
				t.Fatal("nonmatching or incomplete selector was claimed")
			}
		})
	}
	mapped := testSelector()
	mapped.Destination = netip.MustParseAddrPort("[::ffff:192.0.2.7]:3478")
	trace := manager.TryClaim(mapped)
	if trace == nil || !trace.Active() {
		t.Fatal("mapped IPv4 did not match its unmapped literal")
	}
	claimed := snapshotOf(t, manager)
	if claimed.State != StateClaimed || !claimed.Claimed || len(claimed.Events) != 1 || claimed.Events[0].Stage != StageClaimed {
		t.Fatalf("invalid claimed snapshot: %+v", claimed)
	}
	if manager.TryClaim(testSelector()) != nil || manager.TryClaim(mapped) != nil {
		t.Fatal("more than one flow was claimed")
	}
	cleared, err := manager.Clear(claimed.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Arm(cleared.Generation, mapped); err != nil {
		t.Fatal(err)
	}
	if manager.TryClaim(testSelector()) == nil {
		t.Fatal("mapped arm did not normalize its selector")
	}
}

func TestUDPTraceConcurrentSingleClaim(t *testing.T) {
	manager := testManager(t)
	armManager(t, manager)
	const attempts = 64
	start := make(chan struct{})
	results := make(chan *Trace, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- manager.TryClaim(testSelector())
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	claims := 0
	for trace := range results {
		if trace != nil {
			claims++
		}
	}
	if claims != 1 || len(snapshotOf(t, manager).Events) != 1 {
		t.Fatalf("single-flow claim count: %d", claims)
	}
}

func TestUDPTraceFirstStagesAndSanitizedDetails(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	for i := 0; i < MaxEvents*2; i++ {
		trace.Record(StageAcquireEnter, Detail{})
	}
	invalidDetails := []Detail{
		{Error: ErrorKind("private-error-sentinel")},
		{Backend: BackendKind("private-backend-sentinel")},
		{Unsupported: UnsupportedKind("private-unsupported-sentinel")},
		{Bytes: -1, HasBytes: true},
		{Bytes: -1},
	}
	for _, detail := range invalidDetails {
		trace.Record(StageBackendReturn, detail)
	}
	trace.Record(Stage("private-stage-sentinel"), Detail{})
	trace.Record(StageBackendReturn, Detail{Error: ErrorNone, Backend: BackendTransport})
	trace.Record(StageBackendReturn, Detail{Error: ErrorOther})
	trace.Record(StageDecodedReadReturn, Detail{Error: ErrorNone, Bytes: 1, HasBytes: true})
	trace.Record(StageDecodedReadError, Detail{Error: ErrorEOF})
	trace.Record(StageObjectCreated, Detail{Bytes: 12345})
	snapshot := snapshotOf(t, manager)
	wantStages := []Stage{StageClaimed, StageAcquireEnter, StageBackendReturn, StageDecodedReadReturn, StageDecodedReadError, StageObjectCreated}
	if len(snapshot.Events) != len(wantStages) {
		t.Fatalf("unexpected first-stage event count: %d", len(snapshot.Events))
	}
	for i, stage := range wantStages {
		if snapshot.Events[i].Stage != stage || snapshot.Events[i].ElapsedMS < 0 || snapshot.Events[i].ElapsedMS > MaxDuration.Milliseconds() {
			t.Fatalf("invalid event %d: %+v", i, snapshot.Events[i])
		}
	}
	if snapshot.Events[2].Detail.Error != ErrorNone || snapshot.Events[3].Detail.Bytes != 1 ||
		snapshot.Events[4].Detail.Error != ErrorEOF || snapshot.Events[5].Detail != nil {
		t.Fatal("details were overwritten or a missing byte result was invented")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-", "192.0.2.7", "source_port", "destination", "outbound", "selector", "metadata"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot exposed forbidden content %q", secret)
		}
	}
}

func TestUDPTraceSnapshotDeepCopy(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	trace.Record(StagePacketReadReturn, Detail{Error: ErrorNone, Bytes: 0, HasBytes: true})
	fields := &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour, DataFlag: true}
	trace.SetHeader(HeaderSummary{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: fields})
	fields.Status = HeaderStatus("private-mutation-sentinel")
	first := snapshotOf(t, manager)
	if first.Header.Decoded.Status != HeaderNew {
		t.Fatal("header input pointer was retained")
	}
	first.Events[0].Stage = Stage("private-event-sentinel")
	first.Events[1].Detail.Error = ErrorOther
	first.Events[1].Detail.Bytes = 999
	first.Header.Decoded.Status = HeaderOther
	first.Budget.MaxEvents = 0
	second := snapshotOf(t, manager)
	if second.Events[0].Stage != StageClaimed || second.Events[1].Detail.Error != ErrorNone ||
		second.Events[1].Detail.Bytes != 0 || second.Header.Decoded.Status != HeaderNew || second.Budget.MaxEvents != MaxEvents {
		t.Fatal("snapshot mutation changed recorder storage")
	}
	if first.Events[1].Detail == second.Events[1].Detail || first.Header.Decoded == second.Header.Decoded {
		t.Fatal("snapshots share nested pointers")
	}
	manager.mu.Lock()
	storedError := manager.events[1].Detail.Error
	storedStatus := manager.header.Decoded.Status
	manager.mu.Unlock()
	if storedError != ErrorNone || storedStatus != HeaderNew {
		t.Fatal("direct recorder storage did not retain the original data")
	}
}

func TestUDPTraceHeaderProgressAndConcurrentInvalidation(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	trace.SetHeader(HeaderSummary{State: HeaderWaiting, CapturedBytes: 3})
	trace.SetHeader(HeaderSummary{State: HeaderWaiting, CapturedBytes: 2})
	if snapshotOf(t, manager).Header.CapturedBytes != 3 {
		t.Fatal("header progress regressed")
	}
	trace.SetHeader(HeaderSummary{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: HeaderKeep, Length: HeaderLengthLong}})
	trace.SetHeader(HeaderSummary{State: HeaderWaiting, CapturedBytes: PrefixBytes})
	if snapshotOf(t, manager).Header.State != HeaderComplete {
		t.Fatal("waiting replaced the complete summary")
	}
	trace.SetHeader(HeaderSummary{State: HeaderUnknownConcurrent, CapturedBytes: PrefixBytes})
	trace.SetHeader(HeaderSummary{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour}})
	trace.SetHeader(HeaderSummary{State: HeaderWaiting})
	header := snapshotOf(t, manager).Header
	if header.State != HeaderUnknownConcurrent || header.CapturedBytes != 0 || header.Decoded != nil {
		t.Fatalf("concurrent read did not invalidate the summary permanently: %+v", header)
	}
}

func TestUDPTraceClearDropsStorageAndInvalidatesOldWork(t *testing.T) {
	manager := testManager(t)
	oldTrace := claimManager(t, manager)
	oldTrace.Record(StageAcquireReturn, Detail{Error: ErrorNone})
	old := snapshotOf(t, manager)
	cleared, err := manager.Clear(old.Generation)
	if err != nil || cleared.State != StateIdle || cleared.Generation == old.Generation ||
		len(cleared.Events) != 0 || cleared.Claimed || cleared.Header != (HeaderSummary{State: HeaderWaiting}) {
		t.Fatalf("clear did not reset output: %+v, %v", cleared, err)
	}
	manager.mu.Lock()
	storageClear := manager.selector == (Selector{}) && manager.events == nil && manager.timer == nil &&
		manager.seen == 0 && !manager.retained && !manager.claimed && manager.armedAt.IsZero() && manager.deadline.IsZero()
	manager.mu.Unlock()
	if !storageClear || oldTrace.Active() || manager.TryClaim(testSelector()) != nil {
		t.Fatal("clear retained matching storage or an active trace")
	}
	armed, err := manager.Arm(cleared.Generation, testSelector())
	if err != nil {
		t.Fatal(err)
	}
	oldTrace.Record(StagePacketWriteReturn, Detail{Error: ErrorOther, Bytes: 99, HasBytes: true})
	oldTrace.SetHeader(HeaderSummary{State: HeaderUnknownConcurrent})
	oldTrace.Unsupported(UnsupportedType)
	manager.mu.Lock()
	deadline := manager.deadline
	manager.deadline = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.expire(old.Generation)
	manager.mu.Lock()
	stateAfterOldTimer := manager.state
	manager.deadline = deadline
	manager.mu.Unlock()
	if stateAfterOldTimer != StateArmed {
		t.Fatal("old timer changed the new generation")
	}
	if _, err := manager.Clear(old.Generation); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale clear error: %v", err)
	}
	current, err := manager.Snapshot(armed.Generation)
	if err != nil || current.State != StateArmed || current.Claimed || len(current.Events) != 0 || current.Header.State != HeaderWaiting {
		t.Fatalf("old work mutated new observation: %+v, %v", current, err)
	}
	newTrace := manager.TryClaim(testSelector())
	if newTrace == nil {
		t.Fatal("new generation was not claimable")
	}
	newTrace.Record(StageAcquireEnter, Detail{})
	if len(snapshotOf(t, manager).Events) != 2 {
		t.Fatal("current generation is not retrievable after stale operations")
	}
}

func TestUDPTraceExpiryAndStopAreObservationOnly(t *testing.T) {
	for _, claim := range []bool{false, true} {
		t.Run(map[bool]string{false: "armed", true: "claimed"}[claim], func(t *testing.T) {
			manager := testManager(t)
			armed := armManager(t, manager)
			var trace *Trace
			if claim {
				trace = manager.TryClaim(testSelector())
				trace.Record(StageBackendEnter, Detail{Backend: BackendTCP})
			}
			before := snapshotOf(t, manager)
			manager.mu.Lock()
			manager.deadline = time.Now().Add(-time.Millisecond)
			manager.mu.Unlock()
			manager.expire(armed.Generation)
			stopped := snapshotOf(t, manager)
			if stopped.State != StateStopped || stopped.StoppedReason != StopExpired || stopped.RemainingMS != 0 ||
				stopped.Claimed != claim || !reflect.DeepEqual(stopped.Events, before.Events) || trace.Active() {
				t.Fatalf("invalid expiry result: %+v", stopped)
			}
			trace.Record(StageBackendReturn, Detail{Error: ErrorCanceled})
			trace.SetHeader(HeaderSummary{State: HeaderUnknownConcurrent})
			if !reflect.DeepEqual(snapshotOf(t, manager), stopped) || manager.TryClaim(testSelector()) != nil {
				t.Fatal("expired observation continued recording")
			}
			manager.mu.Lock()
			hasTimer := manager.timer != nil
			manager.mu.Unlock()
			if hasTimer {
				t.Fatal("expiry retained its timer")
			}
			if _, err := manager.Arm(stopped.Generation, testSelector()); !errors.Is(err, ErrConflict) {
				t.Fatalf("expired result was overwritten without clear: %v", err)
			}
		})
	}
}

func TestUDPTraceDisableAndFinalClose(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	trace.Record(StageAcquireEnter, Detail{})
	manager.Disable()
	disabled := snapshotOf(t, manager)
	if disabled.State != StateDisabled || disabled.StoppedReason != StopDisabled || trace.Active() || disabled.RemainingMS != 0 {
		t.Fatalf("invalid disabled state: %+v", disabled)
	}
	trace.Record(StageAcquireReturn, Detail{Error: ErrorNone})
	if !reflect.DeepEqual(snapshotOf(t, manager), disabled) {
		t.Fatal("disable did not freeze records")
	}
	if _, err := manager.Arm(disabled.Generation, testSelector()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled arm error: %v", err)
	}
	if _, err := manager.Clear(disabled.Generation); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled clear error: %v", err)
	}
	manager.Enable()
	retained := snapshotOf(t, manager)
	if retained.State != StateStopped || !reflect.DeepEqual(retained.Events, disabled.Events) {
		t.Fatal("enable discarded retained results")
	}
	if _, err := manager.Arm(retained.Generation, testSelector()); !errors.Is(err, ErrConflict) {
		t.Fatalf("enable allowed overwriting retained result: %v", err)
	}
	cleared, err := manager.Clear(retained.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Arm(cleared.Generation, testSelector()); err != nil {
		t.Fatal(err)
	}
	currentTrace := manager.TryClaim(testSelector())
	manager.Close()
	manager.Close()
	manager.Enable()
	manager.Disable()
	closed := snapshotOf(t, manager)
	if closed.State != StateClosed || closed.StoppedReason != StopClosed || currentTrace.Active() || manager.TryClaim(testSelector()) != nil {
		t.Fatalf("close was not final: %+v", closed)
	}
	if _, err := manager.Arm(closed.Generation, testSelector()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed arm error: %v", err)
	}
	if _, err := manager.Clear(closed.Generation); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed clear error: %v", err)
	}
	manager.mu.Lock()
	cleaned := manager.timer == nil && manager.selector == (Selector{})
	manager.mu.Unlock()
	if !cleaned {
		t.Fatal("close retained a timer or matching key")
	}
}

func TestUDPTraceUnsupportedAndFlowClose(t *testing.T) {
	for _, reason := range []UnsupportedKind{UnsupportedUDPConnect, UnsupportedMultiplex, UnsupportedEncoding, UnsupportedType, UnsupportedCapabilities} {
		t.Run(string(reason), func(t *testing.T) {
			manager := testManager(t)
			trace := claimManager(t, manager)
			trace.Unsupported(UnsupportedKind("private-reason-sentinel"))
			trace.Unsupported("")
			if !trace.Active() {
				t.Fatal("invalid unsupported enum stopped observation")
			}
			trace.Unsupported(reason)
			snapshot := snapshotOf(t, manager)
			if snapshot.State != StateStopped || snapshot.StoppedReason != StopUnsupported ||
				len(snapshot.Events) != 2 || snapshot.Events[1].Stage != StageUnsupported || snapshot.Events[1].Detail.Unsupported != reason || trace.Active() {
				t.Fatalf("invalid unsupported result: %+v", snapshot)
			}
		})
	}
	manager := testManager(t)
	trace := claimManager(t, manager)
	trace.Record(StageClose, Detail{Error: ErrorNone})
	snapshot := snapshotOf(t, manager)
	if snapshot.State != StateStopped || snapshot.StoppedReason != StopFlowClosed || len(snapshot.Events) != 2 || trace.Active() {
		t.Fatalf("invalid flow-close result: %+v", snapshot)
	}
}

func TestUDPTraceEventCapAndResponseBudget(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	trace.SetHeader(HeaderSummary{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: HeaderKeepAlive, Length: HeaderLengthLong, DataFlag: true, ErrorFlag: true}})
	// The closed first-stage list is smaller than the hard cap; seed only the cap boundary.
	manager.mu.Lock()
	manager.events = make([]Event, MaxEvents-1)
	for i := range manager.events {
		manager.events[i] = Event{Stage: StageDecodedReadReturn, ElapsedMS: MaxDuration.Milliseconds(), Detail: &Detail{
			Error: ErrorUnexpectedEOF, Backend: BackendTransport, Unsupported: UnsupportedCapabilities,
			Bytes: int(^uint(0) >> 1), HasBytes: true,
		}}
	}
	manager.seen = StageClaimed.bit()
	manager.mu.Unlock()
	trace.Record(StageBackendReturn, Detail{Error: ErrorUnexpectedEOF, Backend: BackendTransport, Unsupported: UnsupportedCapabilities, Bytes: int(^uint(0) >> 1), HasBytes: true})
	snapshot := snapshotOf(t, manager)
	if snapshot.State != StateStopped || snapshot.StoppedReason != StopEventBudget || len(snapshot.Events) != MaxEvents || trace.Active() {
		t.Fatalf("event cap did not stop observation: %+v", snapshot)
	}
	trace.Record(StagePacketWriteReturn, Detail{Error: ErrorOther})
	if !reflect.DeepEqual(snapshotOf(t, manager), snapshot) {
		t.Fatal("event cap did not freeze records")
	}
	encoded, err := json.Marshal(struct {
		Snapshot Snapshot `json:"snapshot"`
	}{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > MaxResponseBytes {
		t.Fatalf("bounded snapshot envelope exceeds %d bytes: %d", MaxResponseBytes, len(encoded)+1)
	}
}

func TestUDPTraceConcurrentRecordSnapshotAndClear(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	generation := snapshotOf(t, manager).Generation
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 50; j++ {
				trace.Record(StageAcquireReturn, Detail{Error: ErrorNone})
				trace.Record(StagePacketReadReturn, Detail{Error: ErrorNone, Bytes: j, HasBytes: true})
				trace.SetHeader(HeaderSummary{State: HeaderWaiting, CapturedBytes: j % PrefixBytes})
				snapshot, err := manager.Snapshot("")
				if err != nil || len(snapshot.Events) > MaxEvents {
					t.Error("concurrent snapshot was unavailable or unbounded")
					return
				}
				if len(snapshot.Events) > 0 {
					snapshot.Events[0].Stage = Stage("caller-owned-mutation")
				}
			}
		}()
	}
	cleared, err := manager.Clear(generation)
	if err != nil {
		t.Fatal(err)
	}
	armed, err := manager.Arm(cleared.Generation, testSelector())
	if err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	snapshot, err := manager.Snapshot(armed.Generation)
	if err != nil || len(snapshot.Events) != 0 || snapshot.State != StateArmed || snapshot.Header.CapturedBytes != 0 {
		t.Fatalf("old concurrent work contaminated new generation: %+v, %v", snapshot, err)
	}
}

func TestUDPTraceNilAndZeroValues(t *testing.T) {
	var nilManager *Manager
	for _, manager := range []*Manager{nilManager, new(Manager)} {
		manager.Enable()
		manager.Disable()
		manager.Close()
		if manager.TryClaim(testSelector()) != nil {
			t.Fatal("nil/zero manager claimed a flow")
		}
		if _, err := manager.Snapshot(""); !errors.Is(err, ErrDisabled) {
			t.Fatalf("unavailable snapshot error: %v", err)
		}
		if _, err := manager.Arm("", testSelector()); !errors.Is(err, ErrDisabled) {
			t.Fatalf("unavailable arm error: %v", err)
		}
		if _, err := manager.Clear(""); !errors.Is(err, ErrDisabled) {
			t.Fatalf("unavailable clear error: %v", err)
		}
	}
	var nilTrace *Trace
	for _, trace := range []*Trace{nilTrace, new(Trace)} {
		trace.Record(StagePacketReadReturn, Detail{Error: ErrorEOF})
		trace.SetHeader(HeaderSummary{State: HeaderUnknownConcurrent})
		trace.Unsupported(UnsupportedType)
		if trace.Active() {
			t.Fatal("nil/zero trace is active")
		}
	}
}

func TestUDPTraceGenerationDoesNotWrap(t *testing.T) {
	manager := testManager(t)
	trace := claimManager(t, manager)
	generation := snapshotOf(t, manager).Generation
	manager.mu.Lock()
	manager.sequence = ^uint64(0)
	manager.mu.Unlock()
	if _, err := manager.Clear(generation); !errors.Is(err, ErrClosed) {
		t.Fatalf("generation overflow error: %v", err)
	}
	closed := snapshotOf(t, manager)
	if closed.State != StateClosed || closed.Generation != generation || trace.Active() {
		t.Fatal("generation overflow reused an identifier or retained an active trace")
	}
}
