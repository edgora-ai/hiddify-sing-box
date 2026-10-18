package dns

import (
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// ResponseHandler prepares the DNS wire payload immediately before delivery.
// A nil replacement preserves the payload. The handler must copy anything it
// retains from wire: its buffer belongs to the writer after preparation.
// If complete is non-nil, it is called exactly once with the write result.
// Packet writers report incomplete delivery through their returned error.
type ResponseHandler func(wire []byte) (replacement []byte, complete func(error))

// ResponseHandlerFactory captures state for one successfully parsed query,
// before ExchangeAsync starts. It is not called again when the response arrives.
// A nil factory or handler leaves the response bytes and delivery path unchanged.
type ResponseHandlerFactory func() ResponseHandler

func captureResponseHandler(factory ResponseHandlerFactory) ResponseHandler {
	if factory == nil {
		return nil
	}
	return factory()
}

// WritePacketResponseWithResponseObserver truncates to the client's UDP limit
// before preparing the response. handler must already have been captured for
// this query, not obtained from a factory when the response arrives.
// The packet writer owns the final buffer, including on write failure.
func WritePacketResponseWithResponseObserver(message *mDNS.Msg, response *mDNS.Msg, writer N.PacketWriter, destination M.Socksaddr, handler ResponseHandler) error {
	frontHeadroom := N.CalculateFrontHeadroom(writer)
	rearHeadroom := N.CalculateRearHeadroom(writer)
	buffer, err := dns.TruncateDNSMessage(message, response, frontHeadroom, rearHeadroom)
	if err != nil {
		return err
	}
	buffer, complete := prepareResponseBuffer(buffer, frontHeadroom, rearHeadroom, handler)
	err = writer.WritePacket(buffer, destination)
	// WritePacket may have consumed, cleared and released buffer. Do not read it.
	if complete != nil {
		complete(err)
	}
	return err
}

func prepareResponseBuffer(buffer *buf.Buffer, frontHeadroom int, rearHeadroom int, handler ResponseHandler) (*buf.Buffer, func(error)) {
	if handler == nil {
		return buffer, nil
	}
	replacement, complete := handler(buffer.Bytes())
	if replacement == nil {
		return buffer, complete
	}
	replacementBuffer := buf.NewSize(frontHeadroom + len(replacement) + rearHeadroom)
	replacementBuffer.Resize(frontHeadroom, 0)
	copy(replacementBuffer.Extend(len(replacement)), replacement)
	// replacement may alias the original buffer, so copy before releasing.
	buffer.Release()
	return replacementBuffer, complete
}
