package v2raywebsocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"

	"github.com/stretchr/testify/require"
)

type hUpgradePipeDialer struct {
	conn        net.Conn
	destination M.Socksaddr
	calls       int
}

func (d *hUpgradePipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != N.NetworkTCP || destination != d.destination || d.calls != 0 {
		return nil, fmt.Errorf("unexpected WebSocket transport dial: %s %s", network, destination)
	}
	d.calls++
	return d.conn, nil
}

func (d *hUpgradePipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("WebSocket fixture must not dial UDP")
}

func hUpgradeResponse(t *testing.T, peer net.Conn, frames []byte, buffered int) (<-chan *http.Request, <-chan error) {
	t.Helper()
	requests := make(chan *http.Request, 1)
	done := make(chan error, 1)
	go func() {
		defer peer.Close()
		if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			done <- err
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(peer))
		if err != nil {
			done <- err
			return
		}
		requests <- request
		accept := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(accept[:]) + "\r\n"
		if protocol := request.Header.Get("Sec-WebSocket-Protocol"); protocol != "" {
			response += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
		}
		response += "\r\n"
		// One pipe write puts the upgrade and this frame prefix in one buffered read.
		if len(response)+buffered > ws.DefaultClientReadBufferSize {
			done <- fmt.Errorf("fixture exceeds the upgrade reader capacity")
			return
		}
		_, err = peer.Write(append([]byte(response), frames[:buffered]...))
		if err == nil && buffered < len(frames) {
			_, err = peer.Write(frames[buffered:])
		}
		done <- err
	}()
	t.Cleanup(func() {
		peer.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("WebSocket fixture did not stop")
		}
	})
	return requests, done
}

func TestH_WebsocketUpgradeBufferedFrames(t *testing.T) {
	for _, test := range []struct {
		name      string
		payloads  [][]byte
		buffered  int
		earlyMode string
	}{
		{"complete_frame", [][]byte{[]byte("first response")}, -1, ""},
		{"partial_frame_header", [][]byte{[]byte("first response")}, 1, ""},
		{"partial_frame_payload", [][]byte{[]byte("first response")}, 7, ""},
		{"multiple_frames", [][]byte{[]byte("first response"), []byte("second response")}, -1, ""},
		{"extended_frame_length", [][]byte{bytes.Repeat([]byte{0x5a}, 300)}, -1, ""},
		{"large_frame_prefix", [][]byte{bytes.Repeat([]byte{0x5a}, 8192)}, 128, ""},
		{"no_buffered_frame", [][]byte{[]byte("later response")}, 0, ""},
		{"early_data_path", [][]byte{[]byte("early response")}, -1, "path"},
		{"early_data_header", [][]byte{[]byte("early response")}, -1, "header"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire, expected bytes.Buffer
			for _, payload := range test.payloads {
				require.NoError(t, ws.WriteFrame(&wire, ws.NewBinaryFrame(payload)))
				expected.Write(payload)
			}
			buffered := test.buffered
			if buffered < 0 {
				buffered = wire.Len()
			}
			raw, peer := net.Pipe()
			t.Cleanup(func() { raw.Close() })
			requests, _ := hUpgradeResponse(t, peer, wire.Bytes(), buffered)
			destination := M.ParseSocksaddr("websocket.test:443")
			dialer := &hUpgradePipeDialer{conn: raw, destination: destination}
			options := option.V2RayWebsocketOptions{Path: "/ws/"}
			earlyData := []byte("synthetic early request")
			if test.earlyMode != "" {
				options.MaxEarlyData = uint32(len(earlyData))
				if test.earlyMode == "header" {
					options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				}
			}
			client, err := NewClient(context.Background(), dialer, destination, options, nil)
			require.NoError(t, err)
			conn, err := client.DialContext(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, dialer.calls)
			if test.earlyMode != "" {
				n, err := conn.Write(earlyData)
				require.NoError(t, err)
				require.Equal(t, len(earlyData), n)
			}
			var request *http.Request
			select {
			case request = <-requests:
			case <-time.After(3 * time.Second):
				t.Fatal("no in-memory upgrade request received")
			}
			encodedEarly := base64.RawURLEncoding.EncodeToString(earlyData)
			if test.earlyMode == "path" {
				require.Equal(t, "/ws/"+encodedEarly, request.URL.Path)
			} else {
				require.Equal(t, "/ws/", request.URL.Path)
			}
			if test.earlyMode == "header" {
				require.Equal(t, encodedEarly, request.Header.Get("Sec-WebSocket-Protocol"))
			}
			actual := make([]byte, expected.Len())
			// Small reads exercise cached-prefix consumption before the underlying stream.
			for offset := 0; offset < len(actual); {
				end := min(offset+3, len(actual))
				n, err := io.ReadFull(conn, actual[offset:end])
				require.NoError(t, err, "response bytes lost after upgrade at offset %d", offset)
				offset += n
			}
			require.Equal(t, expected.Bytes(), actual)
			var trailing [1]byte
			n, err := conn.Read(trailing[:])
			require.Zero(t, n)
			require.ErrorIs(t, err, io.EOF)
			// Close the transport directly: the peer has already ended the fixture.
			if websocket, ok := conn.(*WebsocketConn); ok {
				require.NoError(t, websocket.Conn.Close())
			} else {
				require.NoError(t, conn.(*EarlyWebsocketConn).conn.Load().Conn.Close())
			}
		})
	}
}
