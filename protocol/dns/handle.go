package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

func HandleStreamDNSRequest(ctx context.Context, router adapter.DNSRouter, conn net.Conn, metadata adapter.InboundContext) error {
	return HandleStreamDNSRequestWithResponseObserver(ctx, router, conn, metadata, nil)
}

func HandleStreamDNSRequestWithResponseObserver(ctx context.Context, router adapter.DNSRouter, conn net.Conn, metadata adapter.InboundContext, factory ResponseHandlerFactory) error {
	var queryLength uint16
	err := binary.Read(conn, binary.BigEndian, &queryLength)
	if err != nil {
		return err
	}
	if queryLength == 0 {
		return dns.RcodeFormatError
	}
	buffer := buf.NewSize(int(queryLength))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(conn, int(queryLength))
	if err != nil {
		return err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	if err != nil {
		return err
	}
	handler := captureResponseHandler(factory)
	metadataInQuery := metadata
	router.ExchangeAsync(adapter.WithContext(ctx, &metadataInQuery), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
		if err != nil {
			conn.Close()
			return
		}
		go writeStreamResponse(conn, response, handler)
	})
	return nil
}

func writeStreamResponse(conn net.Conn, response *mDNS.Msg, handler ResponseHandler) error {
	responseLength := response.Len()
	responseBuffer := buf.NewSize(3 + responseLength)
	defer func() { responseBuffer.Release() }()
	responseBuffer.Resize(2, 0)
	wire, err := response.PackBuffer(responseBuffer.FreeBytes())
	if err != nil {
		return err
	}
	// PackBuffer may allocate its own backing array when compression needs
	// scratch space larger than the final wire. Always copy the returned wire.
	copy(responseBuffer.Extend(len(wire)), wire)
	responseBuffer, complete := prepareResponseBuffer(responseBuffer, 2, 0, handler)
	if responseBuffer.Len() > mDNS.MaxMsgSize {
		err = mDNS.ErrBuf
	} else {
		wireLength := responseBuffer.Len()
		binary.BigEndian.PutUint16(responseBuffer.ExtendHeader(2), uint16(wireLength))
		frameLength := responseBuffer.Len()
		var n int
		n, err = conn.Write(responseBuffer.Bytes())
		if err == nil && n != frameLength {
			err = io.ErrShortWrite
		}
	}
	if complete != nil {
		complete(err)
	}
	return err
}

func NewDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, cachedPackets []*N.PacketBuffer, metadata adapter.InboundContext) error {
	return NewDNSPacketConnectionWithResponseObserver(ctx, router, conn, cachedPackets, metadata, nil)
}

func NewDNSPacketConnectionWithResponseObserver(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, cachedPackets []*N.PacketBuffer, metadata adapter.InboundContext, factory ResponseHandlerFactory) error {
	metadata.Destination = M.Socksaddr{}
	var reader N.PacketReader = conn
	var counters []N.CountFunc
	cachedPackets = common.Reverse(cachedPackets)
	for {
		reader, counters = N.UnwrapCountPacketReader(reader, counters)
		if cachedReader, isCached := reader.(N.CachedPacketReader); isCached {
			packet := cachedReader.ReadCachedPacket()
			if packet != nil {
				cachedPackets = append(cachedPackets, packet)
				continue
			}
		}
		if readWaiter, created := bufio.CreatePacketReadWaiter(reader); created {
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{})
			return newDNSPacketConnection(ctx, router, conn, readWaiter, counters, cachedPackets, metadata, factory)
		}
		break
	}
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var message mDNS.Msg
			var destination M.Socksaddr
			var err error
			if len(cachedPackets) > 0 {
				packet := cachedPackets[0]
				cachedPackets = cachedPackets[1:]
				for _, counter := range counters {
					counter(int64(packet.Buffer.Len()))
				}
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				destination = packet.Destination
				N.PutPacketBuffer(packet)
				if err != nil {
					cancel(err)
					return err
				}
			} else {
				buffer := buf.NewPacket()
				destination, err = conn.ReadPacket(buffer)
				if err != nil {
					buffer.Release()
					cancel(err)
					return err
				}
				for _, counter := range counters {
					counter(int64(buffer.Len()))
				}
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			handler := captureResponseHandler(factory)
			metadataInQuery := metadata
			router.ExchangeAsync(adapter.WithContext(ctx, &metadataInQuery), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
				if err != nil {
					cancel(err)
					return
				}
				timeout.Update()
				writeErr := WritePacketResponseWithResponseObserver(&message, response, conn, destination, handler)
				if writeErr != nil {
					cancel(writeErr)
				}
			})
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}

func newDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, readWaiter N.PacketReadWaiter, readCounters []N.CountFunc, cached []*N.PacketBuffer, metadata adapter.InboundContext, factory ResponseHandlerFactory) error {
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var (
				message     mDNS.Msg
				destination M.Socksaddr
				err         error
				buffer      *buf.Buffer
			)
			if len(cached) > 0 {
				packet := cached[0]
				cached = cached[1:]
				for _, counter := range readCounters {
					counter(int64(packet.Buffer.Len()))
				}
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				destination = packet.Destination
				N.PutPacketBuffer(packet)
				if err != nil {
					cancel(err)
					return err
				}
			} else {
				buffer, destination, err = readWaiter.WaitReadPacket()
				if err != nil {
					cancel(err)
					return err
				}
				for _, counter := range readCounters {
					counter(int64(buffer.Len()))
				}
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			handler := captureResponseHandler(factory)
			metadataInQuery := metadata
			router.ExchangeAsync(adapter.WithContext(ctx, &metadataInQuery), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
				if err != nil {
					cancel(err)
					return
				}
				timeout.Update()
				writeErr := WritePacketResponseWithResponseObserver(&message, response, conn, destination, handler)
				if writeErr != nil {
					cancel(writeErr)
				}
			})
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}
