package udptrace

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	mu            sync.Mutex
	claimable     atomic.Bool
	namespace     string
	sequence      uint64
	generation    string
	state         State
	retained      bool
	claimed       bool
	selector      Selector
	armedAt       time.Time
	deadline      time.Time
	timer         *time.Timer
	seen          uint32
	events        []Event
	header        HeaderSummary
	stoppedReason StopReason
}

type Trace struct {
	manager    *Manager
	generation string
}

func NewManager() (*Manager, error) {
	return newManager(rand.Reader)
}

func newManager(entropy io.Reader) (*Manager, error) {
	var namespace [16]byte
	if _, err := io.ReadFull(entropy, namespace[:]); err != nil {
		return nil, ErrDisabled
	}
	name := hex.EncodeToString(namespace[:])
	return &Manager{
		namespace:  name,
		generation: name + "-0",
		state:      StateDisabled,
		header:     HeaderSummary{State: HeaderWaiting},
	}, nil
}

func (m *Manager) Enable() {
	if m == nil || m.namespace == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateDisabled {
		if m.retained {
			m.state = StateStopped
		} else {
			m.state = StateIdle
		}
	}
}

func (m *Manager) Disable() {
	if m == nil || m.namespace == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateClosed {
		return
	}
	m.stopLocked(StopDisabled)
	m.state = StateDisabled
}

func (m *Manager) Close() {
	if m == nil || m.namespace == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(StopClosed)
	m.state = StateClosed
	m.selector = Selector{}
}

func (m *Manager) Arm(expectedGeneration string, selector Selector) (Snapshot, error) {
	if m == nil || m.namespace == "" {
		return Snapshot{}, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkMutationLocked(expectedGeneration); err != nil {
		return Snapshot{}, err
	}
	if err := selector.Validate(); err != nil {
		return Snapshot{}, err
	}
	now := time.Now()
	m.expireLocked(now)
	if m.state != StateIdle || m.retained {
		return Snapshot{}, ErrConflict
	}
	if err := m.advanceLocked(); err != nil {
		return Snapshot{}, err
	}
	selector = selector.normalized()
	selector.Outbound = strings.Clone(selector.Outbound)
	m.selector = selector
	m.state = StateArmed
	m.retained = true
	m.claimed = false
	m.armedAt = now
	m.deadline = now.Add(MaxDuration)
	m.events = make([]Event, 0, MaxEvents)
	m.seen = 0
	m.header = HeaderSummary{State: HeaderWaiting}
	m.stoppedReason = ""
	generation := m.generation
	m.timer = time.AfterFunc(time.Until(m.deadline), func() { m.expire(generation) })
	m.claimable.Store(true)
	now = time.Now()
	m.expireLocked(now)
	return m.snapshotLocked(now), nil
}

func (m *Manager) Snapshot(expectedGeneration string) (Snapshot, error) {
	if m == nil || m.namespace == "" {
		return Snapshot{}, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if expectedGeneration != "" && expectedGeneration != m.generation {
		return Snapshot{}, ErrGeneration
	}
	now := time.Now()
	m.expireLocked(now)
	return m.snapshotLocked(now), nil
}

func (m *Manager) Clear(expectedGeneration string) (Snapshot, error) {
	if m == nil || m.namespace == "" {
		return Snapshot{}, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkMutationLocked(expectedGeneration); err != nil {
		return Snapshot{}, err
	}
	if err := m.advanceLocked(); err != nil {
		return Snapshot{}, err
	}
	m.stopTimerLocked()
	m.claimable.Store(false)
	m.state = StateIdle
	m.retained = false
	m.claimed = false
	m.selector = Selector{}
	m.armedAt = time.Time{}
	m.deadline = time.Time{}
	m.events = nil
	m.seen = 0
	m.header = HeaderSummary{State: HeaderWaiting}
	m.stoppedReason = ""
	return m.snapshotLocked(time.Now()), nil
}

func (m *Manager) TryClaim(selector Selector) *Trace {
	if m == nil || !m.claimable.Load() || selector.Validate() != nil {
		return nil
	}
	selector = selector.normalized()
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.expireLocked(now)
	if m.state != StateArmed || selector != m.selector {
		return nil
	}
	m.claimable.Store(false)
	m.claimed = true
	m.state = StateClaimed
	m.recordLocked(StageClaimed, Detail{}, now)
	return &Trace{manager: m, generation: m.generation}
}

func (m *Manager) checkMutationLocked(expectedGeneration string) error {
	if m.state == StateClosed {
		return ErrClosed
	}
	if m.state == StateDisabled {
		return ErrDisabled
	}
	if expectedGeneration == "" || expectedGeneration != m.generation {
		return ErrGeneration
	}
	return nil
}

func (m *Manager) advanceLocked() error {
	if m.sequence == ^uint64(0) {
		m.stopLocked(StopClosed)
		m.state = StateClosed
		m.selector = Selector{}
		return ErrClosed
	}
	m.sequence++
	m.generation = m.namespace + "-" + strconv.FormatUint(m.sequence, 16)
	return nil
}

func (m *Manager) expire(generation string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation == m.generation {
		m.expireLocked(time.Now())
	}
}

func (m *Manager) expireLocked(now time.Time) {
	if (m.state == StateArmed || m.state == StateClaimed) && !now.Before(m.deadline) {
		m.stopLocked(StopExpired)
	}
}

func (m *Manager) stopTimerLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
}

func (m *Manager) stopLocked(reason StopReason) {
	m.claimable.Store(false)
	m.stopTimerLocked()
	if m.state == StateArmed || m.state == StateClaimed {
		m.state = StateStopped
		m.stoppedReason = reason
	}
}

func (m *Manager) snapshotLocked(now time.Time) Snapshot {
	remaining := int64(0)
	if m.state == StateArmed || m.state == StateClaimed {
		remaining = m.deadline.Sub(now).Milliseconds()
		if remaining < 0 {
			remaining = 0
		} else if remaining > MaxDuration.Milliseconds() {
			remaining = MaxDuration.Milliseconds()
		}
	}
	events := make([]Event, len(m.events))
	for i, event := range m.events {
		events[i] = event
		if event.Detail != nil {
			detail := *event.Detail
			events[i].Detail = &detail
		}
	}
	return Snapshot{
		State:       m.state,
		Generation:  m.generation,
		RemainingMS: remaining,
		Budget: Budget{
			DurationMS:       MaxDuration.Milliseconds(),
			MaxFlows:         1,
			MaxEvents:        MaxEvents,
			PrefixBytes:      PrefixBytes,
			MaxResponseBytes: MaxResponseBytes,
		},
		Claimed:       m.claimed,
		Events:        events,
		StoppedReason: m.stoppedReason,
		Header:        m.header.clone(),
	}
}

func (m *Manager) traceActiveLocked(generation string, now time.Time) bool {
	if generation != m.generation {
		return false
	}
	m.expireLocked(now)
	return m.state == StateClaimed
}

func (m *Manager) recordLocked(stage Stage, detail Detail, now time.Time) {
	bit := stage.bit()
	if bit == 0 || !detail.valid() || m.seen&bit != 0 {
		return
	}
	if len(m.events) >= MaxEvents {
		m.stopLocked(StopEventBudget)
		return
	}
	if !detail.HasBytes {
		detail.Bytes = 0
	}
	stage = Stage(strings.Clone(string(stage)))
	detail.Error = ErrorKind(strings.Clone(string(detail.Error)))
	detail.Backend = BackendKind(strings.Clone(string(detail.Backend)))
	detail.Unsupported = UnsupportedKind(strings.Clone(string(detail.Unsupported)))
	elapsed := now.Sub(m.armedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	} else if elapsed > MaxDuration.Milliseconds() {
		elapsed = MaxDuration.Milliseconds()
	}
	event := Event{Stage: stage, ElapsedMS: elapsed}
	if detail != (Detail{}) {
		event.Detail = &detail
	}
	m.events = append(m.events, event)
	m.seen |= bit
	switch {
	case len(m.events) == MaxEvents:
		m.stopLocked(StopEventBudget)
	case stage == StageClose:
		m.stopLocked(StopFlowClosed)
	case stage == StageUnsupported:
		m.stopLocked(StopUnsupported)
	}
}

func (t *Trace) Active() bool {
	if t == nil || t.manager == nil {
		return false
	}
	m := t.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.traceActiveLocked(t.generation, time.Now())
}

func (t *Trace) Record(stage Stage, detail Detail) {
	if t == nil || t.manager == nil {
		return
	}
	m := t.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.traceActiveLocked(t.generation, now) {
		m.recordLocked(stage, detail, now)
	}
}

func (t *Trace) SetHeader(header HeaderSummary) {
	if t == nil || t.manager == nil || !header.valid() {
		return
	}
	m := t.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.traceActiveLocked(t.generation, time.Now()) || m.header.State == HeaderUnknownConcurrent {
		return
	}
	if header.State == HeaderUnknownConcurrent {
		m.header = HeaderSummary{State: HeaderUnknownConcurrent}
		return
	}
	if m.header.State == HeaderComplete || header.CapturedBytes < m.header.CapturedBytes {
		return
	}
	m.header = header.clone()
}

func (t *Trace) Unsupported(reason UnsupportedKind) {
	if reason == "" || !reason.valid() {
		return
	}
	t.Record(StageUnsupported, Detail{Unsupported: reason})
}
