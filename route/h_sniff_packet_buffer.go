package route

import "github.com/sagernet/sing/common/buf"

// compactSniffPacketBuffer takes ownership of a fresh, zero-headroom receive
// buffer. Keep the receive allocation large; only compact after a successful read.
func compactSniffPacketBuffer(buffer *buf.Buffer, isIOS bool) *buf.Buffer {
	if !isIOS || buffer.Start() != 0 || buffer.Cap() != buffer.RawCap() || buffer.Len() > buffer.Cap()/2 {
		return buffer
	}
	compacted := buf.NewSize(buffer.Len())
	// Logical capacity alone does not describe the allocator's minimum pool class.
	if cap(compacted.Bytes()) >= cap(buffer.Bytes()) {
		compacted.Release()
		return buffer
	}
	copy(compacted.Extend(buffer.Len()), buffer.Bytes())
	buffer.Release()
	return compacted
}
