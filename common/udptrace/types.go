package udptrace

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxDuration      = 30 * time.Second
	MaxEvents        = 32
	PrefixBytes      = 6
	MaxResponseBytes = 8 * 1024
	MaxTagBytes      = 256
)

var (
	ErrDisabled        = errors.New("udp_trace_disabled")
	ErrClosed          = errors.New("udp_trace_closed")
	ErrConflict        = errors.New("udp_trace_conflict")
	ErrGeneration      = errors.New("udp_trace_generation")
	ErrInvalidSelector = errors.New("udp_trace_invalid_selector")
)

type Selector struct {
	Network     string
	SourcePort  uint16
	Destination netip.AddrPort
	Outbound    string
}

func (s Selector) Validate() error {
	if s.Network != "udp" || s.SourcePort == 0 || !s.Destination.IsValid() ||
		s.Destination.Port() == 0 || s.Destination.Addr().Zone() != "" ||
		len(s.Outbound) == 0 || len(s.Outbound) > MaxTagBytes || !utf8.ValidString(s.Outbound) {
		return ErrInvalidSelector
	}
	return nil
}

func (s Selector) normalized() Selector {
	s.Network = "udp"
	s.Destination = netip.AddrPortFrom(s.Destination.Addr().Unmap(), s.Destination.Port())
	return s
}

type State string

const (
	StateDisabled State = "disabled"
	StateIdle     State = "idle"
	StateArmed    State = "armed"
	StateClaimed  State = "claimed"
	StateStopped  State = "stopped"
	StateClosed   State = "closed"
)

type Stage string

const (
	StageClaimed           Stage = "claimed"
	StageAcquireEnter      Stage = "acquire_enter"
	StageAcquireReturn     Stage = "acquire_return"
	StageBackendEnter      Stage = "backend_enter"
	StageBackendReturn     Stage = "backend_return"
	StageObjectCreated     Stage = "object_created"
	StagePacketReadEnter   Stage = "packet_read_enter"
	StagePacketReadReturn  Stage = "packet_read_return"
	StagePacketWriteEnter  Stage = "packet_write_enter"
	StagePacketWriteReturn Stage = "packet_write_return"
	StageDecodedReadEnter  Stage = "decoded_read_enter"
	StageDecodedReadReturn Stage = "decoded_read_return"
	StageDecodedReadError  Stage = "decoded_read_error"
	StageClose             Stage = "close"
	StageUnsupported       Stage = "unsupported"
)

func (s Stage) bit() uint32 {
	switch s {
	case StageClaimed:
		return 1 << 0
	case StageAcquireEnter:
		return 1 << 1
	case StageAcquireReturn:
		return 1 << 2
	case StageBackendEnter:
		return 1 << 3
	case StageBackendReturn:
		return 1 << 4
	case StageObjectCreated:
		return 1 << 5
	case StagePacketReadEnter:
		return 1 << 6
	case StagePacketReadReturn:
		return 1 << 7
	case StagePacketWriteEnter:
		return 1 << 8
	case StagePacketWriteReturn:
		return 1 << 9
	case StageDecodedReadEnter:
		return 1 << 10
	case StageDecodedReadReturn:
		return 1 << 11
	case StageDecodedReadError:
		return 1 << 12
	case StageClose:
		return 1 << 13
	case StageUnsupported:
		return 1 << 14
	default:
		return 0
	}
}

type ErrorKind string

const (
	ErrorNone          ErrorKind = "none"
	ErrorEOF           ErrorKind = "eof"
	ErrorUnexpectedEOF ErrorKind = "unexpected_eof"
	ErrorCanceled      ErrorKind = "canceled"
	ErrorDeadline      ErrorKind = "deadline"
	ErrorClosed        ErrorKind = "closed"
	ErrorTimeout       ErrorKind = "timeout"
	ErrorOther         ErrorKind = "other"
)

func (e ErrorKind) valid() bool {
	switch e {
	case "", ErrorNone, ErrorEOF, ErrorUnexpectedEOF, ErrorCanceled, ErrorDeadline, ErrorClosed, ErrorTimeout, ErrorOther:
		return true
	default:
		return false
	}
}

type BackendKind string

const (
	BackendTransport BackendKind = "transport"
	BackendTLS       BackendKind = "tls"
	BackendTCP       BackendKind = "tcp"
)

func (b BackendKind) valid() bool {
	switch b {
	case "", BackendTransport, BackendTLS, BackendTCP:
		return true
	default:
		return false
	}
}

type UnsupportedKind string

const (
	UnsupportedUDPConnect   UnsupportedKind = "udp_connect"
	UnsupportedMultiplex    UnsupportedKind = "multiplex"
	UnsupportedEncoding     UnsupportedKind = "encoding"
	UnsupportedType         UnsupportedKind = "type"
	UnsupportedCapabilities UnsupportedKind = "capabilities"
)

func (u UnsupportedKind) valid() bool {
	switch u {
	case "", UnsupportedUDPConnect, UnsupportedMultiplex, UnsupportedEncoding, UnsupportedType, UnsupportedCapabilities:
		return true
	default:
		return false
	}
}

type Detail struct {
	Error       ErrorKind       `json:"error,omitempty"`
	Backend     BackendKind     `json:"backend,omitempty"`
	Unsupported UnsupportedKind `json:"unsupported,omitempty"`
	Bytes       int             `json:"bytes,omitempty"`
	HasBytes    bool            `json:"has_bytes,omitempty"`
}

func (d Detail) valid() bool {
	return d.Error.valid() && d.Backend.valid() && d.Unsupported.valid() && d.Bytes >= 0
}

// A zero byte result is distinct from a method that has no byte result.
func (d Detail) MarshalJSON() ([]byte, error) {
	var byteCount *int
	if d.HasBytes {
		byteCount = &d.Bytes
	}
	return json.Marshal(struct {
		Error       ErrorKind       `json:"error,omitempty"`
		Backend     BackendKind     `json:"backend,omitempty"`
		Unsupported UnsupportedKind `json:"unsupported,omitempty"`
		Bytes       *int            `json:"bytes,omitempty"`
		HasBytes    bool            `json:"has_bytes,omitempty"`
	}{d.Error, d.Backend, d.Unsupported, byteCount, d.HasBytes})
}

type Event struct {
	Stage     Stage   `json:"stage"`
	ElapsedMS int64   `json:"elapsed_ms"`
	Detail    *Detail `json:"detail,omitempty"`
}

type HeaderState string

const (
	HeaderWaiting           HeaderState = "waiting"
	HeaderComplete          HeaderState = "complete"
	HeaderUnknownConcurrent HeaderState = "unknown_concurrent"
)

type HeaderStatus string

const (
	HeaderNew       HeaderStatus = "new"
	HeaderKeep      HeaderStatus = "keep"
	HeaderEnd       HeaderStatus = "end"
	HeaderKeepAlive HeaderStatus = "keep_alive"
	HeaderOther     HeaderStatus = "other"
)

func (s HeaderStatus) valid() bool {
	switch s {
	case HeaderNew, HeaderKeep, HeaderEnd, HeaderKeepAlive, HeaderOther:
		return true
	default:
		return false
	}
}

type HeaderLength string

const (
	HeaderLengthShort HeaderLength = "short"
	HeaderLengthFour  HeaderLength = "four"
	HeaderLengthLong  HeaderLength = "long"
)

func (l HeaderLength) valid() bool {
	switch l {
	case HeaderLengthShort, HeaderLengthFour, HeaderLengthLong:
		return true
	default:
		return false
	}
}

type HeaderSummary struct {
	State         HeaderState   `json:"state"`
	CapturedBytes int           `json:"captured_bytes"`
	Decoded       *HeaderFields `json:"decoded,omitempty"`
}

type HeaderFields struct {
	Status    HeaderStatus `json:"status"`
	Length    HeaderLength `json:"length"`
	DataFlag  bool         `json:"data_flag"`
	ErrorFlag bool         `json:"error_flag"`
}

func (h HeaderSummary) valid() bool {
	if h.CapturedBytes < 0 || h.CapturedBytes > PrefixBytes {
		return false
	}
	switch h.State {
	case HeaderWaiting, HeaderUnknownConcurrent:
		return h.Decoded == nil
	case HeaderComplete:
		return h.CapturedBytes == PrefixBytes && h.Decoded != nil &&
			h.Decoded.Status.valid() && h.Decoded.Length.valid()
	default:
		return false
	}
}

func (h HeaderSummary) clone() HeaderSummary {
	h.State = HeaderState(strings.Clone(string(h.State)))
	if h.Decoded != nil {
		fields := *h.Decoded
		fields.Status = HeaderStatus(strings.Clone(string(fields.Status)))
		fields.Length = HeaderLength(strings.Clone(string(fields.Length)))
		h.Decoded = &fields
	}
	return h
}

type StopReason string

const (
	StopExpired     StopReason = "expired"
	StopEventBudget StopReason = "event_budget"
	StopDisabled    StopReason = "disabled"
	StopClosed      StopReason = "closed"
	StopFlowClosed  StopReason = "flow_closed"
	StopUnsupported StopReason = "unsupported"
)

type Budget struct {
	DurationMS       int64 `json:"duration_ms"`
	MaxFlows         int   `json:"max_flows"`
	MaxEvents        int   `json:"max_events"`
	PrefixBytes      int   `json:"prefix_bytes"`
	MaxResponseBytes int   `json:"max_response_bytes"`
}

type Snapshot struct {
	State         State         `json:"state"`
	Generation    string        `json:"generation"`
	RemainingMS   int64         `json:"remaining_ms"`
	Budget        Budget        `json:"budget"`
	Claimed       bool          `json:"claimed"`
	Events        []Event       `json:"events"`
	StoppedReason StopReason    `json:"stopped_reason,omitempty"`
	Header        HeaderSummary `json:"header"`
}
