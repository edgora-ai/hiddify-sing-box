package route

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func hSniffPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*37 + 11)
	}
	return payload
}

func hSniffSTUN(size, trailing int) []byte {
	payload := hSniffPayload(size + trailing)
	binary.BigEndian.PutUint16(payload[:2], 1)
	binary.BigEndian.PutUint16(payload[2:4], uint16(size-20))
	binary.BigEndian.PutUint32(payload[4:8], 0x2112a442)
	return payload
}

func hSniffFreshBuffer(t *testing.T, capacity int, payload []byte) *buf.Buffer {
	t.Helper()
	buffer := buf.NewSize(capacity)
	t.Cleanup(buffer.Release)
	n, err := buffer.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	return buffer
}

func TestH_SniffPacketBufferClassesAndDetachment(t *testing.T) {
	for _, test := range []struct {
		size    int
		backing int
		shrink  bool
	}{
		{0, 0, true}, {20, 64, true}, {80, 128, true},
		{64, 64, true}, {65, 128, true}, {128, 128, true}, {129, 256, true},
		{4096, 4096, true}, {4097, 8192, false}, {8192, 8192, false},
	} {
		t.Run(fmt.Sprint(test.size), func(t *testing.T) {
			payload := hSniffPayload(test.size)
			received := hSniffFreshBuffer(t, 8192, payload)
			oldBacking := received.Bytes()[:cap(received.Bytes())]
			retained := compactSniffPacketBuffer(received, true)
			defer retained.Release()
			require.Equal(t, test.backing, cap(retained.Bytes()), "actual pooled backing, not logical buffer length")
			require.True(t, bytes.Equal(payload, retained.Bytes()), "complete payload")
			require.Zero(t, retained.Start())
			if !test.shrink {
				require.Same(t, received, retained)
				require.Equal(t, 8192, received.Cap())
				return
			}
			require.NotSame(t, received, retained)
			require.Zero(t, received.Cap(), "old receive buffer must be released")
			if len(payload) > 0 {
				require.False(t, &oldBacking[0] == &retained.Bytes()[0], "distinct backing addresses")
			}
			// Poison the released backing immediately, before any other allocation.
			// This is deterministic even when sync.Pool chooses not to recycle it.
			for i := range oldBacking {
				oldBacking[i] = 0xa5
			}
			require.True(t, bytes.Equal(payload, retained.Bytes()), "retained bytes must be detached from receive backing")
		})
	}
}

func TestH_SniffPacketBufferSTUNTrailingBytes(t *testing.T) {
	for _, size := range []int{20, 80} {
		for _, trailing := range []int{0, 37} {
			t.Run(fmt.Sprintf("%d+%d", size, trailing), func(t *testing.T) {
				payload := hSniffSTUN(size, trailing)
				received := hSniffFreshBuffer(t, 8192, payload)
				retained := compactSniffPacketBuffer(received, true)
				defer retained.Release()
				require.NotSame(t, received, retained)
				require.Equal(t, payload, retained.Bytes(), "STUN length must not trim padding, trailing or coalesced bytes")
				var metadata adapter.InboundContext
				require.NoError(t, sniff.PeekPacket(context.Background(), &metadata, retained.Bytes(), sniff.STUNMessage))
				require.Equal(t, C.ProtocolSTUN, metadata.Protocol)
			})
		}
	}
}

func TestH_SniffPacketBufferUntouched(t *testing.T) {
	for _, test := range []struct {
		name     string
		capacity int
		size     int
		ios      bool
		start    int
		reserve  int
	}{
		{"zero-buffer", 0, 0, true, 0, 0},
		{"non-ios-empty", 8192, 0, false, 0, 0},
		{"non-ios-small", 8192, 20, false, 0, 0},
		{"non-ios-half", 8192, 4096, false, 0, 0},
		{"minimum-class", 64, 20, true, 0, 0},
		{"same-class-65", 128, 65, true, 0, 0},
		{"same-class-129", 256, 129, true, 0, 0},
		{"above-half", 8192, 4097, true, 0, 0},
		{"full", 8192, 8192, true, 0, 0},
		{"prepared-front", 8192, 20, true, 32, 0},
		{"prepared-rear", 8192, 20, true, 0, 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			received := buf.NewSize(test.capacity)
			defer received.Release()
			received.Resize(test.start, 0)
			received.Reserve(test.reserve)
			payload := hSniffPayload(test.size)
			n, err := received.Write(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			oldBacking := received.Bytes()
			retained := compactSniffPacketBuffer(received, test.ios)
			defer retained.Release()
			require.Same(t, received, retained)
			require.Equal(t, test.capacity-test.reserve, retained.Cap())
			require.Equal(t, test.start, retained.Start())
			require.True(t, bytes.Equal(payload, retained.Bytes()), "complete payload")
			if len(payload) > 0 {
				require.True(t, &oldBacking[0] == &retained.Bytes()[0])
			}
		})
	}
}

func TestH_SniffPacketBufferRetainedBackingTotals(t *testing.T) {
	for _, size := range []int{20, 80} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var buffers []*buf.Buffer
			defer func() {
				for _, buffer := range buffers {
					buffer.Release()
				}
			}()
			var before, after int
			for range 512 {
				received := hSniffFreshBuffer(t, 8192, hSniffSTUN(size, 0))
				before += cap(received.Bytes())
				retained := compactSniffPacketBuffer(received, true)
				buffers = append(buffers, retained)
				after += cap(retained.Bytes())
			}
			want := 512 * 64
			if size == 80 {
				want = 512 * 128
			}
			require.Equal(t, 512*8192, before)
			require.Equal(t, want, after)
			t.Logf("512 retained %dB datagrams: actual backing %d -> %d bytes (not physical footprint)", size, before, after)
		})
	}
}

type hSniffPacketSource struct {
	packets      [][]byte
	destinations []M.Socksaddr
	received     []*buf.Buffer
	capacities   []int
	deadlines    []time.Time
	index        int
	closes       int
	readErr      error
}

func (s *hSniffPacketSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	s.received = append(s.received, buffer)
	s.capacities = append(s.capacities, buffer.Cap())
	if s.readErr != nil {
		return M.Socksaddr{}, s.readErr
	}
	if s.index == len(s.packets) {
		return M.Socksaddr{}, io.EOF
	}
	payload, destination := s.packets[s.index], s.destinations[s.index]
	s.index++
	n, err := buffer.Write(payload)
	if err == nil && n != len(payload) {
		err = io.ErrShortBuffer
	}
	return destination, err
}

func (*hSniffPacketSource) WritePacket(*buf.Buffer, M.Socksaddr) error {
	return errors.New("unexpected fixture write")
}
func (s *hSniffPacketSource) Close() error              { s.closes++; return nil }
func (*hSniffPacketSource) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (*hSniffPacketSource) SetDeadline(time.Time) error { return nil }
func (s *hSniffPacketSource) SetReadDeadline(deadline time.Time) error {
	s.deadlines = append(s.deadlines, deadline)
	return nil
}
func (*hSniffPacketSource) SetWriteDeadline(time.Time) error { return nil }

func TestH_SniffPacketBufferActionReceive(t *testing.T) {
	for _, size := range []int{0, 20, 80, buf.UDPBufferSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := hSniffPayload(size)
			destination := M.Socksaddr{Fqdn: "packet.example", Port: 3478}
			source := &hSniffPacketSource{packets: [][]byte{payload}, destinations: []M.Socksaddr{destination}}
			var seen bool
			action := &R.RuleActionSniff{SnifferNames: []string{"fixture"}, PacketSniffers: []sniff.PacketSniffer{
				func(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
					seen = true
					require.Equal(t, payload, packet)
					if C.IsIos && size <= buf.UDPBufferSize/2 {
						require.Zero(t, source.received[0].Cap(), "compaction must precede PeekPacket")
					} else {
						require.Equal(t, buf.UDPBufferSize, source.received[0].Cap())
					}
					metadata.Protocol = C.ProtocolSTUN
					return nil
				},
			}}
			router := &Router{logger: log.NewNOPFactory().NewLogger("sniff-buffer-test")}
			metadata := &adapter.InboundContext{Destination: destination}
			stream, packets, err := router.actionSniff(context.Background(), metadata, action, nil, source, nil, nil)
			defer N.ReleaseMultiPacketBuffer(packets)
			require.NoError(t, err)
			require.Nil(t, stream)
			require.True(t, seen)
			require.Equal(t, []int{buf.UDPBufferSize}, source.capacities, "receive capacity must not be reduced")
			require.Len(t, packets, 1)
			require.Equal(t, destination, packets[0].Destination)
			require.Equal(t, destination, metadata.Destination)
			require.Equal(t, payload, packets[0].Buffer.Bytes())
			require.Equal(t, C.ProtocolSTUN, metadata.Protocol)
			require.Len(t, source.deadlines, 2)
			require.False(t, source.deadlines[0].IsZero())
			require.True(t, source.deadlines[1].IsZero())
		})
	}
}

func TestH_SniffPacketBufferActionReadErrors(t *testing.T) {
	for _, readErr := range []error{io.EOF, context.DeadlineExceeded} {
		source := &hSniffPacketSource{readErr: readErr}
		router := &Router{logger: log.NewNOPFactory().NewLogger("sniff-buffer-test")}
		metadata := &adapter.InboundContext{}
		_, packets, err := router.actionSniff(context.Background(), metadata, &R.RuleActionSniff{}, nil, source, nil, nil)
		require.Empty(t, packets)
		require.Len(t, source.received, 1)
		require.Zero(t, source.received[0].Cap(), "failed receive must release without retention")
		if errors.Is(readErr, context.DeadlineExceeded) {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, readErr)
		}
	}
}

func TestH_SniffPacketBufferCachedOwnership(t *testing.T) {
	for _, mode := range []string{"close-before-read", "read-packet", "read-cached-packet"} {
		t.Run(mode, func(t *testing.T) {
			payload := hSniffSTUN(80, 37)
			received := hSniffFreshBuffer(t, 8192, payload)
			retained := compactSniffPacketBuffer(received, true)
			defer retained.Release()
			destination := M.Socksaddr{Fqdn: "cache.example", Port: 3478}
			source := &hSniffPacketSource{}
			cached := bufio.NewCachedPacketConn(source, retained, destination)
			retained.Release()
			require.Equal(t, payload, retained.Bytes(), "cache owns a ref until consumed or closed")
			switch mode {
			case "close-before-read":
				require.NoError(t, cached.Close())
				require.Zero(t, retained.Cap())
				require.Nil(t, cached.ReadCachedPacket())
			case "read-packet":
				output := buf.NewSize(len(payload))
				defer output.Release()
				gotDestination, err := cached.ReadPacket(output)
				require.NoError(t, err)
				require.Equal(t, destination, gotDestination)
				require.Equal(t, payload, output.Bytes())
				require.Zero(t, retained.Cap())
				require.NoError(t, cached.Close())
			case "read-cached-packet":
				packet := cached.ReadCachedPacket()
				require.NotNil(t, packet)
				require.Same(t, retained, packet.Buffer)
				require.Equal(t, destination, packet.Destination)
				require.Nil(t, cached.ReadCachedPacket())
				require.NoError(t, cached.Close())
				require.Equal(t, payload, packet.Buffer.Bytes(), "Close must not release transferred ownership")
				packet.Buffer.Release()
				N.PutPacketBuffer(packet)
				require.Zero(t, retained.Cap(), "transferred ref must be releasable by its consumer")
			}
			require.NoError(t, cached.Close())
			require.Zero(t, retained.Cap())
			require.Equal(t, 2, source.closes)
		})
	}
}

func hSniffCachedPackets(t *testing.T, payloads [][]byte, destinations []M.Socksaddr) (N.PacketConn, []*buf.Buffer) {
	t.Helper()
	var packets []*N.PacketBuffer
	var retained []*buf.Buffer
	for i, payload := range payloads {
		received := hSniffFreshBuffer(t, 8192, payload)
		buffer := compactSniffPacketBuffer(received, true)
		retained = append(retained, buffer)
		packet := N.NewPacketBuffer()
		*packet = N.PacketBuffer{Buffer: buffer, Destination: destinations[i]}
		packets = append(packets, packet)
	}
	var conn N.PacketConn = &hSniffPacketSource{}
	// Same ownership transfer and reverse wrapping as routePacketConnection.
	for _, packet := range slices.Backward(packets) {
		conn = bufio.NewCachedPacketConn(conn, packet.Buffer, packet.Destination)
		N.PutPacketBuffer(packet)
	}
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return conn, retained
}

func TestH_SniffPacketBufferCachedOrderAndDestination(t *testing.T) {
	payloads := [][]byte{hSniffSTUN(20, 37), hSniffSTUN(80, 0), hSniffPayload(4096)}
	destinations := []M.Socksaddr{{Fqdn: "first.example", Port: 1}, {Fqdn: "second.example", Port: 2}, {Fqdn: "third.example", Port: 3}}
	conn, retained := hSniffCachedPackets(t, payloads, destinations)
	for i, payload := range payloads {
		output := buf.NewPacket()
		destination, err := conn.ReadPacket(output)
		require.NoError(t, err)
		require.Equal(t, payload, output.Bytes())
		require.Equal(t, destinations[i], destination)
		output.Release()
		require.Zero(t, retained[i].Cap())
	}
	output := buf.NewPacket()
	defer output.Release()
	_, err := conn.ReadPacket(output)
	require.ErrorIs(t, err, io.EOF)
}

type hSniffHeadroomWriter struct {
	payloads     [][]byte
	destinations []M.Socksaddr
}

func (*hSniffHeadroomWriter) FrontHeadroom() int { return 37 }
func (*hSniffHeadroomWriter) RearHeadroom() int  { return 29 }
func (w *hSniffHeadroomWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if buffer.Start() < w.FrontHeadroom() || buffer.FreeLen() < w.RearHeadroom() {
		return fmt.Errorf("missing headroom: front=%d rear=%d", buffer.Start(), buffer.FreeLen())
	}
	w.payloads = append(w.payloads, bytes.Clone(buffer.Bytes()))
	w.destinations = append(w.destinations, destination)
	copy(buffer.ExtendHeader(w.FrontHeadroom()), bytes.Repeat([]byte{0xa5}, w.FrontHeadroom()))
	copy(buffer.Extend(w.RearHeadroom()), bytes.Repeat([]byte{0x5a}, w.RearHeadroom()))
	return nil
}

func TestH_SniffPacketBufferCachedForwardingHeadroom(t *testing.T) {
	payloads := [][]byte{hSniffSTUN(20, 37), hSniffSTUN(80, 37), hSniffPayload(4096)}
	destinations := []M.Socksaddr{{Fqdn: "first.example", Port: 1}, {Fqdn: "second.example", Port: 2}, {Fqdn: "third.example", Port: 3}}
	conn, retained := hSniffCachedPackets(t, payloads, destinations)
	writer := new(hSniffHeadroomWriter)
	n, err := bufio.CopyPacket(writer, conn)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, int64(len(payloads[0])+len(payloads[1])+len(payloads[2])), n)
	require.Equal(t, payloads, writer.payloads)
	require.Equal(t, destinations, writer.destinations)
	for _, buffer := range retained {
		require.Zero(t, buffer.Cap())
	}
}

func TestH_SniffPacketBufferQUICFragmentLifetime(t *testing.T) {
	// Captured Chromium Initials from common/sniff/quic_test.go, TestSniffQUICChromium.
	// These exercise real decryption and CRYPTO reassembly, not synthetic metadata.
	var metadata, baseline adapter.InboundContext
	for i, encoded := range hSniffQUICInitials {
		payload, err := hex.DecodeString(encoded)
		require.NoError(t, err)
		received := hSniffFreshBuffer(t, 8192, payload)
		oldBacking := received.Bytes()[:cap(received.Bytes())]
		retained := compactSniffPacketBuffer(received, true)
		require.NotSame(t, received, retained)
		for j := range oldBacking {
			oldBacking[j] = 0xa5
		}
		sniffErr := sniff.PeekPacket(context.Background(), &metadata, retained.Bytes(), sniff.QUICClientHello)
		baselineErr := sniff.PeekPacket(context.Background(), &baseline, bytes.Clone(payload), sniff.QUICClientHello)
		if i == 0 {
			require.ErrorIs(t, sniffErr, sniff.ErrNeedMoreData)
			require.ErrorIs(t, baselineErr, sniff.ErrNeedMoreData)
			require.NotNil(t, metadata.SniffContext)
		} else {
			require.NoError(t, sniffErr)
			require.NoError(t, baselineErr)
		}
		// Neither stored fragments nor completed SNI may refer to retained input.
		clear(retained.Bytes())
		retained.Release()
		require.Equal(t, baseline.Protocol, metadata.Protocol)
		require.Equal(t, baseline.Client, metadata.Client)
		require.Equal(t, baseline.Domain, metadata.Domain)
	}
	require.Equal(t, C.ProtocolQUIC, metadata.Protocol)
	require.Equal(t, "google.com", metadata.Domain)
	require.Nil(t, metadata.SniffContext)
}

var hSniffQUICInitials = []string{
	"c30000000108f40d654cc09b27f5000044d08a94548e57e43cc5483f129986187c432d58d46674830442988f869566a6e31e2ae37c9f7acbf61cc816" +
		"21594fab0b3dfdc1635460b32389563dc8e74006315661cd22694114612973c1c45910621713a48b375854f095e8a77ccf3afa64e972f0f7f7002f50" +
		"e0b014b1b146ea47c07fb20b73ad5587872b51a0b3fafdf1c4cf4fe6f8b112142392efa25d993abe2f42582be145148bdfe12edcd96c3655b65a4781" +
		"b093e5594ba8e3ae5320f12e8314fc3ca374128cc43381046c322b964681ed4395c813b28534505118201459665a44b8f0abead877de322e9040631d" +
		"20b05f15b81fa7ff785d4041aecc37c7e2ccdc5d1532787ce566517e8985fd5c200dbfd1e67bc255efaba94cfc07bb52fea4a90887413b134f2715b5" +
		"643542aa897c6116486f428d82da64d2a2c1e1bdd40bd592558901a554b003d6966ac5a7b8b9413eddbf6ef21f28386c74981e3ce1d724c341e95494" +
		"907626659692720c81114ca4acea35a14c402cfa3dc2228446e78dc1b81fa4325cf7e314a9cad6a6bdff33b3351dcba74eb15fae67f1227283aa4cdd" +
		"64bcadf8f19358333f8549b596f4350297b5c65274565869d497398339947b9d3d064e5b06d39d34b436d8a41c1a3880de10bd26c3b1c5b4e2a49b0d" +
		"4d07b8d90cd9e92bc611564d19ea8ec33099e92033caf21f5307dbeaa4708b99eb313bff99e2081ac25fd12d6a72e8335e0724f6718fe023cd0ad0d6" +
		"e6a6309f09c9c391eec2bc08e9c3210a043c08e1759f354c121f6517fff4d6e20711a871e41285d48d930352fddffb92c96ba57df045ce99f8bfdfa8" +
		"edc0969ce68a51e9fbb4f54b956d9df74a9e4af27ed2b27839bce1cffeca8333c0aaee81a570217442f9029ba8fedb84a2cf4be4d910982d891ea00e" +
		"816c7fb98e8020e896a9c6fdd9106611da0a99dde18df1b7a8f6327acb1eed9ad93314451e48cb0dfb9571728521ca3db2ac0968159d5622556a55d5" +
		"1a422d11995b650949aaefc5d24c16080446dfc4fbc10353f9f93ce161ab513367bb89ab83988e0630b689e174e27bcfcc31996ee7b0bca909e251b8" +
		"2d69a28fee5a5d662e127508cd19dbbe5097b7d5b62a49203d66764197a527e472e2627e44a93d44177dace9d60e7d0e03305ddf4cfe47cdf2362e14" +
		"de79ef46a6763ce696cd7854a48d9419a0817507a4713ffd4977b906d4f2b5fb6dbe1bd15bc505d5fea582190bf531a45d5ee026da8918547fd5105f" +
		"15e5d061c7b0cf80a34990366ed8e91e13c2f0d85e5dad537298808d193cf54b7eaac33f10051f74cb6b75e52f81618c36f03d86aef613ba237a1a79" +
		"3ba1539938a38f62ccaf7bd5f6c5e0ce53cde4012fcf2b758214a0422d2faaa798e86e19d7481b42df2b36a73d287ff28c20cce01ce598771fec16a8" +
		"f1f00305c06010126013a6c1de9f589b4e79d693717cd88ad1c42a2d99fa96617ba0bc6365b68e21a70ebc447904aa27979e1514433cfd83bfec09f1" +
		"37c747d47582cb63eb28f873fb94cf7a59ff764ddfbb687d79a58bb10f85949269f7f72c611a5e0fbb52adfa298ff060ec2eb7216fd7302ea8fb0779" +
		"8cbb3be25cb53ac8161aac2b5bbcfbcfb01c113d28bd1cb0333fb89ac82a95930f7abded0a2f5a623cc6a1f62bf3f38ef1b81c1e50a634f657dbb677" +
		"0e4af45879e2fb1e00c742e7b52205c8015b5c0f5b1e40186ff9aa7288ab3e01a51fb87761f9bc6837082af109b39cc9f620",
	"c90000000108f40d654cc09b27f5000044d073eb38807026d4088455e650e7ccf750d01a72f15f9bfc8ff40d223499db1a485cff14dbd45b9be11817" +
		"2834dc35dca3cf62f61a1266f40b92faf3d28d67a466cfdca678ddced15cd606d31959cf441828467857b226d1a241847c82c57312cefe68ba5042d9" +
		"29919bcd4403b39e5699fe87dda05df1b3801e048edee792458e9b1a9b1d4039df05847bcee3be567494b5876e3bd4c3220fe9dfdb2c07d77410f907" +
		"f744251ef15536cc03b267d3668d5b75bc1ad2fe735cd3bb73519dd9f1625a49e17ad27bdeccf706c83b5ea339a0a05dd0072f4a8f162bd29926b499" +
		"7f05613c6e4b0270b0c02805ca0543f27c1ff8505a5750bdd33529ee73c491050a10c6903f53c1121dbe0380e84c007c8df74a1b02443ed80ba7766a" +
		"ef5549e618d4fd249844ee28565142005369869299e8c3035ecef3d799f6cada8549e75b4ce4cbf4c85ef071fd7ff067b1ca9b5968dc41d13d011f6d" +
		"7843823bac97acb1eb8ee45883f0f254b5f9bd4c763b67e2d8c70a7618a0ef0de304cf597a485126e09f8b2fd795b394c0b4bc4cd2634c2057970da2" +
		"c798c5e8af7aed4f76f5e25d04e3f8c9c5a5b150d17e0d4c74229898c69b8dc7b8bcc9d359eb441de75c68fbdebec62fb669dcccfb1aad03e3fa073a" +
		"db2ccf7bb14cbaf99e307d2c903ee71a8f028102eb510caee7e7397512086a78d1f95635c7d06845b5a708652dc4e5cd61245aae5b3c05b84815d84d" +
		"367bce9b9e3f6d6b90701ac3679233c14d5ce2a1eff26469c966266dc6284bdb95c9c6158934c413a872ce22101e4163e3293d236b301592ca4ccacc" +
		"1fd4c37066e79c2d9857c8a2560dcf0b33b19163c4240c471b19907476e7e25c65f7eb37276594a0f6b4c33c340cc3284178f17ac5e34dbe7509db89" +
		"0e4ddfd0540fbf9deb32a0101d24fe58b26c5f81c627db9d6ae59d7a111a3d5d1f6109f4eec0d0234e6d73c73a44f50999462724b51ce0fd8283535d" +
		"70d9e83872c79c59897407a0736741011ae5c64862eb0712f9e7b07aa1d5418ca3fde8626257c6fe418f3c5479055bb2b0ab4c25f649923fc2a41c79" +
		"aaa7d0f3af6d8b8cf06f61f0230d09bbb60bb49b9e49cc5973748a6cf7ffdee7804d424f9423c63e7ff22f4bd24e4867636ef9fe8dd37f59941a8a47" +
		"c27765caa8e875a30b62834f17c569227e5e6ed15d58e05d36e76332befad065a2cd4079e66d5af189b0337624c89b1560c3b1b0befd5c1f20e6de8e" +
		"3d664b3ac06b3d154b488983e14aa93266f5f8b621d2a9bb7ccce509eb26e025c9c45f7cccc09ce85b3103af0c93ce9822f82ecb168ca3177829afb2" +
		"ea0da2c380e7b1728add55a5d42632e2290363d4cbe432b67e13691648e1acfab22cf0d551eee857709b428bb78e27a45aff6eca301c02e4d13cf36c" +
		"c2494fdd1aef8dede6e18febd79dca4c6964d09b91c25a08f0947c76ab5104de9404459c2edf5f4adb9dfd771be83656f77fbbafb1ad328171706601" +
		"0be8778952495383c9f2cf0a38527228c662a35171c5981731f1af09bab842fe6c3162ad4152a4221f560eb6f9bea66b294ffbd3643da2fe34096da1" +
		"3c246505452540177a2a0a1a69106e5cfc279a4890fc3be2952f26be245f930e6c2d9e7e26ee960481e72b99594a1185b46b94b6436d00ba6c70ffe1" +
		"35d43907c92c6f1c09fb9453f103730714f5700fa4347f9715c774cb04a7218dacc66d9c2fade18b14e684aa7fc9ebda0a28",
}

func TestH_SniffPacketBufferActionQUICRetry(t *testing.T) {
	payloads := make([][]byte, len(hSniffQUICInitials))
	for i, encoded := range hSniffQUICInitials {
		var err error
		payloads[i], err = hex.DecodeString(encoded)
		require.NoError(t, err)
	}
	destinations := []M.Socksaddr{{Fqdn: "first.example", Port: 443}, {Fqdn: "second.example", Port: 8443}}
	source := &hSniffPacketSource{packets: payloads, destinations: destinations}
	router := &Router{logger: log.NewNOPFactory().NewLogger("sniff-buffer-test")}
	metadata := &adapter.InboundContext{}
	action := &R.RuleActionSniff{SnifferNames: []string{C.ProtocolQUIC}, PacketSniffers: []sniff.PacketSniffer{sniff.QUICClientHello}}
	stream, packets, err := router.actionSniff(context.Background(), metadata, action, nil, source, nil, nil)
	defer N.ReleaseMultiPacketBuffer(packets)
	require.NoError(t, err)
	require.Nil(t, stream)
	require.Len(t, packets, 2)
	for i, packet := range packets {
		require.Equal(t, payloads[i], packet.Buffer.Bytes())
		require.Equal(t, destinations[i], packet.Destination)
	}
	require.Equal(t, []int{buf.UDPBufferSize, buf.UDPBufferSize}, source.capacities)
	require.Len(t, source.deadlines, 4)
	require.False(t, source.deadlines[0].IsZero())
	require.True(t, source.deadlines[1].IsZero())
	require.False(t, source.deadlines[2].IsZero())
	require.True(t, source.deadlines[3].IsZero())
	require.NoError(t, metadata.SniffError)
	require.Equal(t, C.ProtocolQUIC, metadata.Protocol)
	require.Equal(t, "google.com", metadata.Domain)
}

func TestH_SniffPacketBufferFreshClassBoundaries(t *testing.T) {
	for _, test := range []struct{ capacity, size, backing int }{{64, 0, 0}, {128, 64, 64}, {256, 128, 128}} {
		t.Run(fmt.Sprintf("%d/%d", test.capacity, test.size), func(t *testing.T) {
			payload := hSniffPayload(test.size)
			received := hSniffFreshBuffer(t, test.capacity, payload)
			retained := compactSniffPacketBuffer(received, true)
			defer retained.Release()
			require.NotSame(t, received, retained)
			require.Zero(t, received.Cap())
			require.Equal(t, test.backing, cap(retained.Bytes()))
			require.True(t, bytes.Equal(payload, retained.Bytes()))
		})
	}
}
