package vmess

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/udptrace"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *Outbound) claimUDPTrace(ctx context.Context, destination M.Socksaddr) *udptrace.Trace {
	if h.udpTrace == nil {
		return nil
	}
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Network != N.NetworkUDP || destination.IsDomain() || !destination.IsIP() {
		return nil
	}
	destination = destination.Unwrap()
	return h.udpTrace.TryClaim(udptrace.Selector{
		Network:     N.NetworkUDP,
		SourcePort:  metadata.Source.Port,
		Destination: netip.AddrPortFrom(destination.Addr, destination.Port),
		Outbound:    h.Tag(),
	})
}

func (h *Outbound) traceUDPEntry(ctx context.Context, destination M.Socksaddr, connected bool) *udptrace.Trace {
	trace := h.claimUDPTrace(ctx, destination)
	switch {
	case h.multiplexDialer != nil:
		trace.Unsupported(udptrace.UnsupportedMultiplex)
	case connected:
		trace.Unsupported(udptrace.UnsupportedUDPConnect)
	case !h.xudp || h.packetAddr:
		trace.Unsupported(udptrace.UnsupportedEncoding)
	default:
		return trace
	}
	return nil
}

func recordUDPResult(trace *udptrace.Trace, stage udptrace.Stage, err error, n int, hasBytes bool) {
	if trace.Active() {
		trace.Record(stage, udptrace.Detail{
			Error:    udptrace.ClassifyError(err),
			Bytes:    n,
			HasBytes: hasBytes && n >= 0,
		})
	}
}

func observeXUDPPacketConn(conn vmess.PacketConn, trace *udptrace.Trace) vmess.PacketConn {
	if !trace.Active() {
		return conn
	}
	xudp, ok := conn.(*vmess.XUDPConn)
	if !ok || xudp == nil || xudp.Conn == nil {
		trace.Unsupported(udptrace.UnsupportedType)
		return conn
	}
	// The private XUDP writer retains the original connection. Only normal,
	// already-decoded reads pass through this tap; no extra read is performed.
	xudp.Conn = &udpStageReadTap{Conn: xudp.Conn, trace: trace}
	return &udpStagePacketConn{PacketConn: xudp, capabilities: xudp, trace: trace}
}

type udpStageCapabilities interface {
	NeedHandshake() bool
	NeedAdditionalReadDeadline() bool
}

type udpStagePacketConn struct {
	vmess.PacketConn
	capabilities udpStageCapabilities
	trace        *udptrace.Trace
}

var _ vmess.PacketConn = (*udpStagePacketConn)(nil)

func (c *udpStagePacketConn) Read(p []byte) (int, error) {
	c.trace.Record(udptrace.StagePacketReadEnter, udptrace.Detail{})
	n, err := c.PacketConn.Read(p)
	recordUDPResult(c.trace, udptrace.StagePacketReadReturn, err, n, true)
	return n, err
}

func (c *udpStagePacketConn) Write(p []byte) (int, error) {
	c.trace.Record(udptrace.StagePacketWriteEnter, udptrace.Detail{Bytes: len(p), HasBytes: true})
	n, err := c.PacketConn.Write(p)
	recordUDPResult(c.trace, udptrace.StagePacketWriteReturn, err, n, true)
	return n, err
}

func (c *udpStagePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.trace.Record(udptrace.StagePacketReadEnter, udptrace.Detail{})
	n, address, err := c.PacketConn.ReadFrom(p)
	recordUDPResult(c.trace, udptrace.StagePacketReadReturn, err, n, true)
	return n, address, err
}

func (c *udpStagePacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	c.trace.Record(udptrace.StagePacketWriteEnter, udptrace.Detail{Bytes: len(p), HasBytes: true})
	n, err := c.PacketConn.WriteTo(p, address)
	recordUDPResult(c.trace, udptrace.StagePacketWriteReturn, err, n, true)
	return n, err
}

func (c *udpStagePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.trace.Record(udptrace.StagePacketReadEnter, udptrace.Detail{})
	destination, err := c.PacketConn.ReadPacket(buffer)
	var size int
	if err == nil {
		size = buffer.Len()
	}
	recordUDPResult(c.trace, udptrace.StagePacketReadReturn, err, size, err == nil)
	return destination, err
}

func (c *udpStagePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.trace.Record(udptrace.StagePacketWriteEnter, udptrace.Detail{Bytes: buffer.Len(), HasBytes: true})
	err := c.PacketConn.WritePacket(buffer, destination)
	// WritePacket consumes its buffer and has no returned byte count.
	recordUDPResult(c.trace, udptrace.StagePacketWriteReturn, err, 0, false)
	return err
}

func (c *udpStagePacketConn) Close() error {
	err := c.PacketConn.Close()
	recordUDPResult(c.trace, udptrace.StageClose, err, 0, false)
	return err
}

func (c *udpStagePacketConn) NeedHandshake() bool {
	return c.capabilities.NeedHandshake()
}

func (c *udpStagePacketConn) NeedAdditionalReadDeadline() bool {
	return c.capabilities.NeedAdditionalReadDeadline()
}

func (c *udpStagePacketConn) Upstream() any {
	return c.PacketConn
}

// Replacement would bypass observation. Headroom is discovered via Upstream,
// not duplicated on this zero-headroom layer.
func (c *udpStagePacketConn) ReaderReplaceable() bool { return false }
func (c *udpStagePacketConn) WriterReplaceable() bool { return false }

type udpStageReadTap struct {
	net.Conn
	trace  *udptrace.Trace
	prefix udpStagePrefix
}

func (c *udpStageReadTap) Read(p []byte) (int, error) {
	if !c.trace.Active() {
		c.prefix.discard()
		return c.Conn.Read(p)
	}
	tracked, ambiguous := c.prefix.begin()
	if ambiguous {
		c.trace.SetHeader(udptrace.HeaderSummary{State: udptrace.HeaderUnknownConcurrent})
	}
	c.trace.Record(udptrace.StageDecodedReadEnter, udptrace.Detail{})
	n, err := c.Conn.Read(p)
	var observed []byte
	if n > 0 && n <= len(p) {
		observed = p[:n]
	}
	prefix, count, complete, unknown := c.prefix.finish(tracked, observed, c.trace.Active())
	if unknown {
		c.trace.SetHeader(udptrace.HeaderSummary{State: udptrace.HeaderUnknownConcurrent})
	} else if complete {
		c.trace.SetHeader(summarizeUDPStageHeader(prefix))
	} else if tracked {
		c.trace.SetHeader(udptrace.HeaderSummary{State: udptrace.HeaderWaiting, CapturedBytes: count})
	}
	recordUDPResult(c.trace, udptrace.StageDecodedReadReturn, err, n, true)
	if err != nil {
		recordUDPResult(c.trace, udptrace.StageDecodedReadError, err, n, true)
	}
	return n, err
}

func (c *udpStageReadTap) Upstream() any           { return c.Conn }
func (c *udpStageReadTap) ReaderReplaceable() bool { return false }
func (c *udpStageReadTap) WriterReplaceable() bool { return false }

// Only this fixed window retains bytes. The mutex never covers an I/O call;
// overlapping reads invalidate the window instead of imposing a new ordering.
type udpStagePrefix struct {
	mutex     sync.Mutex
	inFlight  int
	closed    bool
	ambiguous bool
	bytes     [udptrace.PrefixBytes]byte
	count     int
}

func (p *udpStagePrefix) begin() (tracked, ambiguous bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.closed {
		return false, p.ambiguous
	}
	p.inFlight++
	if p.inFlight > 1 {
		p.ambiguous = true
		p.closed = true
		p.bytes = [udptrace.PrefixBytes]byte{}
		p.count = 0
	}
	return true, p.ambiguous
}

func (p *udpStagePrefix) finish(tracked bool, value []byte, active bool) (prefix [udptrace.PrefixBytes]byte, count int, complete, unknown bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if tracked {
		p.inFlight--
	}
	if !active {
		p.bytes = [udptrace.PrefixBytes]byte{}
		p.count = 0
		p.closed = true
		return
	}
	if p.ambiguous {
		return prefix, 0, false, true
	}
	if !tracked || p.closed {
		return prefix, p.count, false, false
	}
	p.count += copy(p.bytes[p.count:], value)
	if p.count == len(p.bytes) {
		prefix = p.bytes
		p.bytes = [udptrace.PrefixBytes]byte{}
		p.closed = true
		return prefix, p.count, true, false
	}
	return prefix, p.count, false, false
}

func (p *udpStagePrefix) discard() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.bytes = [udptrace.PrefixBytes]byte{}
	p.count = 0
	p.closed = true
}

func summarizeUDPStageHeader(prefix [udptrace.PrefixBytes]byte) udptrace.HeaderSummary {
	fields := udptrace.HeaderFields{
		Status:    udptrace.HeaderOther,
		DataFlag:  prefix[5]&1 != 0,
		ErrorFlag: prefix[5]&2 != 0,
	}
	switch prefix[4] {
	case vmess.StatusNew:
		fields.Status = udptrace.HeaderNew
	case vmess.StatusKeep:
		fields.Status = udptrace.HeaderKeep
	case vmess.StatusEnd:
		fields.Status = udptrace.HeaderEnd
	case vmess.StatusKeepAlive:
		fields.Status = udptrace.HeaderKeepAlive
	}
	switch length := binary.BigEndian.Uint16(prefix[:2]); {
	case length < 4:
		fields.Length = udptrace.HeaderLengthShort
	case length == 4:
		fields.Length = udptrace.HeaderLengthFour
	default:
		fields.Length = udptrace.HeaderLengthLong
	}
	return udptrace.HeaderSummary{State: udptrace.HeaderComplete, CapturedBytes: udptrace.PrefixBytes, Decoded: &fields}
}
