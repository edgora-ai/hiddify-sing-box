package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/udptrace"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const (
	udpStageTraceTestSecret   = "udp-stage-secret-private-sentinel"
	udpStageTraceTestOutbound = "udp-stage-outbound-private-sentinel"
	udpStageTraceTestRawError = "udp-stage-raw-error-private-sentinel"
	udpStageTraceTestBody     = `{"source_port":53535,"destination":"192.0.2.51:3478","outbound":"` + udpStageTraceTestOutbound + `"}`
)

type udpStageTraceTestEnv struct {
	server  *Server
	manager *udptrace.Manager
	network *hFakeNetworkManager
	dns     *hFakeDNSRouter
}

func udpStageTraceTestContext(t *testing.T) (context.Context, *udpStageTraceTestEnv) {
	t.Helper()
	manager, err := udptrace.NewManager()
	require.NoError(t, err)
	t.Cleanup(manager.Close)
	env := &udpStageTraceTestEnv{
		manager: manager,
		network: &hFakeNetworkManager{},
		dns:     &hFakeDNSRouter{},
	}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.NetworkManager](ctx, env.network)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, env.dns)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &hFakeOutboundManager{direct: &hFakeOutbound{tag: "direct"}})
	ctx = service.ContextWithPtr(ctx, trafficontrol.NewManager())
	logFactory := log.NewNOPFactory()
	ctx = service.ContextWithPtr(ctx, clashmode.NewManager(ctx, logFactory.NewLogger("mode"), "Rule", []string{"Rule", "Global", "Direct"}))
	return ctx, env
}

func newUDPStageTraceTestServer(t *testing.T, options option.ClashAPIOptions, withManager bool) *udpStageTraceTestEnv {
	t.Helper()
	ctx, env := udpStageTraceTestContext(t)
	if withManager {
		ctx = udptrace.ContextWithManager(ctx, env.manager)
	}
	server, err := NewServer(ctx, log.NewNOPFactory(), options)
	require.NoError(t, err)
	env.server = server.(*Server)
	t.Cleanup(func() { require.NoError(t, env.server.Close()) })
	return env
}

func udpStageTraceTestOptions() option.ClashAPIOptions {
	return option.ClashAPIOptions{ExternalController: "127.0.0.1:9090", Secret: udpStageTraceTestSecret}
}

// These methods exercise ResponseController dispatch without a real socket.
// Unsupported-writer cases establish handler-side failure before body access,
// not a bound on net/http or a nonstandard server's later drain/cleanup.
type udpStageTraceDeadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadlines  []time.Time
	writeDeadlines []time.Time
	readErr        error
	writeErr       error
}

func (w *udpStageTraceDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.readDeadlines = append(w.readDeadlines, deadline)
	return w.readErr
}

func (w *udpStageTraceDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.writeDeadlines = append(w.writeDeadlines, deadline)
	return w.writeErr
}

func newUDPStageTraceDeadlineRecorder() *udpStageTraceDeadlineRecorder {
	return &udpStageTraceDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func udpStageTraceTestRequest(method, body, etag string) *http.Request {
	request := httptest.NewRequest(method, udpStageTracePath, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:49152"
	request.Header.Set("Authorization", "Bearer "+udpStageTraceTestSecret)
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	return request
}

func udpStageTraceTestDo(env *udpStageTraceTestEnv, request *http.Request) *udpStageTraceDeadlineRecorder {
	writer := newUDPStageTraceDeadlineRecorder()
	env.server.httpServer.Handler.ServeHTTP(writer, request)
	return writer
}

func udpStageTraceTestSnapshot(t *testing.T, writer *udpStageTraceDeadlineRecorder) udptrace.Snapshot {
	t.Helper()
	require.Equal(t, http.StatusOK, writer.Code, writer.Body.String())
	require.Equal(t, "no-store", writer.Header().Get("Cache-Control"))
	require.Equal(t, "close", writer.Header().Get("Connection"))
	require.LessOrEqual(t, writer.Body.Len(), udptrace.MaxResponseBytes)
	var snapshot udptrace.Snapshot
	require.NoError(t, json.Unmarshal(writer.Body.Bytes(), &snapshot))
	require.Equal(t, strconv.Quote(snapshot.Generation), writer.Header().Get("ETag"))
	return snapshot
}

func udpStageTraceTestDiscover(t *testing.T, env *udpStageTraceTestEnv) string {
	t.Helper()
	writer := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", ""))
	udpStageTraceTestSnapshot(t, writer)
	return writer.Header().Get("ETag")
}

func udpStageTraceTestUnchanged(t *testing.T, env *udpStageTraceTestEnv, before udptrace.Snapshot) {
	t.Helper()
	after, err := env.manager.Snapshot("")
	require.NoError(t, err)
	require.Equal(t, before.Generation, after.Generation)
	require.Equal(t, before.State, after.State)
	require.Equal(t, before.Events, after.Events)
	require.Equal(t, before.Header, after.Header)
}

func udpStageTraceTestError(t *testing.T, writer *udpStageTraceDeadlineRecorder, status int, message *HTTPError) {
	t.Helper()
	require.Equal(t, status, writer.Code, writer.Body.String())
	require.Equal(t, "no-store", writer.Header().Get("Cache-Control"))
	require.Equal(t, "close", writer.Header().Get("Connection"))
	require.Empty(t, writer.Header().Get("ETag"))
	require.LessOrEqual(t, writer.Body.Len(), udptrace.MaxResponseBytes)
	var decoded HTTPError
	require.NoError(t, json.Unmarshal(writer.Body.Bytes(), &decoded))
	require.Equal(t, *message, decoded)
	for _, sentinel := range []string{udpStageTraceTestSecret, udpStageTraceTestOutbound, udpStageTraceTestRawError} {
		require.NotContains(t, writer.Body.String(), sentinel)
	}
}

func TestUDPStageTrace_ControllerGating(t *testing.T) {
	cases := []struct {
		name        string
		controller  string
		secret      string
		withManager bool
		mounted     bool
	}{
		{"ipv4", "127.0.0.1:9090", udpStageTraceTestSecret, true, true},
		{"ipv6", "[::1]:9090", udpStageTraceTestSecret, true, true},
		{"mapped_ipv4", "[::ffff:127.0.0.1]:9090", udpStageTraceTestSecret, true, true},
		{"empty_controller", "", udpStageTraceTestSecret, true, false},
		{"empty_host", ":9090", udpStageTraceTestSecret, true, false},
		{"wildcard_ipv4", "0.0.0.0:9090", udpStageTraceTestSecret, true, false},
		{"wildcard_ipv6", "[::]:9090", udpStageTraceTestSecret, true, false},
		{"lan", "192.168.1.2:9090", udpStageTraceTestSecret, true, false},
		{"hostname", "localhost:9090", udpStageTraceTestSecret, true, false},
		{"zone", "[::1%lo0]:9090", udpStageTraceTestSecret, true, false},
		{"zero_port_ipv4", "127.0.0.1:0", udpStageTraceTestSecret, true, false},
		{"zero_port_ipv6", "[::1]:0", udpStageTraceTestSecret, true, false},
		{"missing_port", "127.0.0.1", udpStageTraceTestSecret, true, false},
		{"invalid_port", "127.0.0.1:65536", udpStageTraceTestSecret, true, false},
		{"empty_secret", "127.0.0.1:9090", "", true, false},
		{"no_manager", "127.0.0.1:9090", udpStageTraceTestSecret, false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := option.ClashAPIOptions{ExternalController: test.controller, Secret: test.secret}
			env := newUDPStageTraceTestServer(t, options, test.withManager)
			writer := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", ""))
			snapshot, err := env.manager.Snapshot("")
			require.NoError(t, err)
			if test.mounted {
				udpStageTraceTestSnapshot(t, writer)
				require.Equal(t, udptrace.StateIdle, snapshot.State)
			} else {
				require.Equal(t, http.StatusNotFound, writer.Code)
				require.Equal(t, udptrace.StateDisabled, snapshot.State)
			}
		})
	}
}

func TestUDPStageTrace_StrictGuard(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*http.Request)
		status  int
		message *HTTPError
	}{
		{"no_auth", func(r *http.Request) { r.Header.Del("Authorization") }, http.StatusUnauthorized, ErrUnauthorized},
		{"wrong_auth", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, http.StatusUnauthorized, ErrUnauthorized},
		{"bearer_case", func(r *http.Request) { r.Header.Set("Authorization", "bearer "+udpStageTraceTestSecret) }, http.StatusUnauthorized, ErrUnauthorized},
		{"extra_space", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  "+udpStageTraceTestSecret) }, http.StatusUnauthorized, ErrUnauthorized},
		{"trailing_space", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+udpStageTraceTestSecret+" ") }, http.StatusUnauthorized, ErrUnauthorized},
		{"duplicate_auth", func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+udpStageTraceTestSecret) }, http.StatusUnauthorized, ErrUnauthorized},
		{"duplicate_auth_case", func(r *http.Request) { r.Header["authorization"] = []string{"Bearer " + udpStageTraceTestSecret} }, http.StatusUnauthorized, ErrUnauthorized},
		{"combined_auth", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+udpStageTraceTestSecret+", Bearer "+udpStageTraceTestSecret)
		}, http.StatusUnauthorized, ErrUnauthorized},
		{"query", func(r *http.Request) { r.URL.RawQuery = "token=" + udpStageTraceTestSecret }, http.StatusBadRequest, ErrBadRequest},
		{"empty_query", func(r *http.Request) { r.URL.ForceQuery = true }, http.StatusBadRequest, ErrBadRequest},
		{"query_request_uri", func(r *http.Request) { r.RequestURI += "?" }, http.StatusBadRequest, ErrBadRequest},
		{"upgrade", func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, http.StatusBadRequest, ErrBadRequest},
		{"empty_upgrade", func(r *http.Request) { r.Header["Upgrade"] = []string{""} }, http.StatusBadRequest, ErrBadRequest},
		{"upgrade_case", func(r *http.Request) { r.Header["uPgRaDe"] = []string{"WebSocket"} }, http.StatusBadRequest, ErrBadRequest},
		{"connection_upgrade", func(r *http.Request) { r.Header.Set("Connection", "keep-alive, UpGrAdE") }, http.StatusBadRequest, ErrBadRequest},
		{"duplicate_connection", func(r *http.Request) { r.Header["Connection"] = []string{"keep-alive", "upgrade"} }, http.StatusBadRequest, ErrBadRequest},
		{"connection_case", func(r *http.Request) { r.Header["connection"] = []string{"upgrade"} }, http.StatusBadRequest, ErrBadRequest},
		{"old_websocket_token_bypass", func(r *http.Request) {
			r.Header.Del("Authorization")
			r.Header.Set("Upgrade", "websocket")
			r.URL.RawQuery = "token=" + udpStageTraceTestSecret
		}, http.StatusUnauthorized, ErrUnauthorized},
		{"lan_peer", func(r *http.Request) { r.RemoteAddr = "192.168.1.2:49152" }, http.StatusForbidden, ErrForbidden},
		{"hostname_peer", func(r *http.Request) { r.RemoteAddr = "localhost:49152" }, http.StatusForbidden, ErrForbidden},
		{"missing_peer_port", func(r *http.Request) { r.RemoteAddr = "127.0.0.1" }, http.StatusForbidden, ErrForbidden},
		{"zero_peer_port_ipv4", func(r *http.Request) { r.RemoteAddr = "127.0.0.1:0" }, http.StatusForbidden, ErrForbidden},
		{"zero_peer_port_ipv6", func(r *http.Request) { r.RemoteAddr = "[::1]:0" }, http.StatusForbidden, ErrForbidden},
		{"forwarded_spoof", func(r *http.Request) {
			r.RemoteAddr = "192.168.1.2:49152"
			r.Header.Set("Forwarded", "for=127.0.0.1")
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			r.Header.Set("X-Real-IP", "127.0.0.1")
		}, http.StatusForbidden, ErrForbidden},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, strconv.Quote(before.Generation))
			test.mutate(request)
			writer := udpStageTraceTestDo(env, request)
			udpStageTraceTestError(t, writer, test.status, test.message)
			udpStageTraceTestUnchanged(t, env, before)
		})
	}
}

func TestUDPStageTrace_CanonicalRouteOnly(t *testing.T) {
	for _, path := range []string{
		udpStageTracePath + "/",
		udpStageTracePath + "/child",
		"/diagnostics//udp-stage",
		"/diagnostics/./udp-stage",
		"/Diagnostics/udp-stage",
		"/%64iagnostics/udp-stage",
		"/diagnostics/%75dp-stage",
		"/diagnostics/udp%2dstage",
		"/diagnostics%2Fudp-stage",
		udpStageTracePath + "%2F",
	} {
		t.Run(path, func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			for _, authenticated := range []bool{false, true} {
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(udpStageTraceTestBody))
				request.RemoteAddr = "127.0.0.1:49152"
				request.Header.Set("If-Match", strconv.Quote(before.Generation))
				if authenticated {
					request.Header.Set("Authorization", "Bearer "+udpStageTraceTestSecret)
				}
				writer := udpStageTraceTestDo(env, request)
				require.Equal(t, http.StatusNotFound, writer.Code)
				udpStageTraceTestUnchanged(t, env, before)
			}
		})
	}
	// Exercise the actual registered route with a nonempty RawPath that Chi
	// can match, so a matching RawPath still cannot bypass the local guard.
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	before, err := env.manager.Snapshot("")
	require.NoError(t, err)
	request := udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, strconv.Quote(before.Generation))
	request.URL.RawPath = udpStageTracePath
	udpStageTraceTestError(t, udpStageTraceTestDo(env, request), http.StatusNotFound, ErrNotFound)
	udpStageTraceTestUnchanged(t, env, before)
}

func TestUDPStageTrace_LoopbackPeerIgnoresForwardingHeaders(t *testing.T) {
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	for _, peer := range []string{"127.0.0.2:49152", "[::1]:49152", "[::ffff:127.0.0.1]:49152"} {
		request := udpStageTraceTestRequest(http.MethodGet, "", "")
		request.RemoteAddr = peer
		request.Header.Set("Forwarded", "for=192.0.2.88")
		request.Header.Set("X-Forwarded-For", "192.0.2.88")
		udpStageTraceTestSnapshot(t, udpStageTraceTestDo(env, request))
	}
}

func TestUDPStageTrace_GenerationSyntax(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		other  bool
	}{
		{"absent", nil, false},
		{"empty", []string{""}, false},
		{"unquoted", []string{"generation"}, false},
		{"wildcard", []string{"*"}, false},
		{"quoted_wildcard", []string{`"*"`}, false},
		{"weak", []string{`W/"generation"`}, false},
		{"list", []string{`"one", "two"`}, false},
		{"duplicate", []string{`"one"`, `"two"`}, false},
		{"case_duplicate", []string{`"one"`}, true},
		{"empty_generation", []string{`""`}, false},
		{"space", []string{`"one two"`}, false},
		{"oversize", []string{strconv.Quote(strings.Repeat("g", udpStageTraceMaxGeneration+1))}, false},
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodGet} {
		for _, test := range cases {
			if method == http.MethodGet && test.name == "absent" {
				continue
			}
			t.Run(method+"/"+test.name, func(t *testing.T) {
				env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
				before, err := env.manager.Snapshot("")
				require.NoError(t, err)
				request := udpStageTraceTestRequest(method, "", "")
				if method == http.MethodPost {
					request = udpStageTraceTestRequest(method, udpStageTraceTestBody, "")
				}
				if test.values != nil {
					request.Header["If-Match"] = test.values
				}
				if test.other {
					request.Header["if-match"] = []string{`"two"`}
				}
				udpStageTraceTestError(t, udpStageTraceTestDo(env, request), http.StatusBadRequest, ErrBadRequest)
				udpStageTraceTestUnchanged(t, env, before)
			})
		}
	}
}

func TestUDPStageTrace_StrictJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"null", "null"},
		{"array", "[]"},
		{"string", `"value"`},
		{"number", "1"},
		{"missing_all", "{}"},
		{"missing_source", `{"destination":"192.0.2.51:3478","outbound":"tag"}`},
		{"missing_destination", `{"source_port":53535,"outbound":"tag"}`},
		{"missing_outbound", `{"source_port":53535,"destination":"192.0.2.51:3478"}`},
		{"unknown", strings.Replace(udpStageTraceTestBody, "}", `,"extra":true}`, 1)},
		{"client_budget", strings.Replace(udpStageTraceTestBody, "}", `,"duration_ms":60000}`, 1)},
		{"client_network", strings.Replace(udpStageTraceTestBody, "}", `,"network":"udp"}`, 1)},
		{"client_generation", strings.Replace(udpStageTraceTestBody, "}", `,"generation":"value"}`, 1)},
		{"duplicate_source", strings.Replace(udpStageTraceTestBody, "}", `,"source_port":53535}`, 1)},
		{"duplicate_destination", strings.Replace(udpStageTraceTestBody, "}", `,"destination":"192.0.2.51:3478"}`, 1)},
		{"duplicate_outbound", strings.Replace(udpStageTraceTestBody, "}", `,"outbound":"tag"}`, 1)},
		{"escaped_duplicate", strings.Replace(udpStageTraceTestBody, "}", `,"source`+string(rune(92))+`u005fport":53535}`, 1)},
		{"case_source", strings.Replace(udpStageTraceTestBody, "source_port", "Source_Port", 1)},
		{"case_destination", strings.Replace(udpStageTraceTestBody, "destination", "Destination", 1)},
		{"case_outbound", strings.Replace(udpStageTraceTestBody, "outbound", "OUTBOUND", 1)},
		{"null_source", strings.Replace(udpStageTraceTestBody, "53535", "null", 1)},
		{"null_destination", strings.Replace(udpStageTraceTestBody, `"192.0.2.51:3478"`, "null", 1)},
		{"null_outbound", strings.Replace(udpStageTraceTestBody, strconv.Quote(udpStageTraceTestOutbound), "null", 1)},
		{"source_zero", strings.Replace(udpStageTraceTestBody, "53535", "0", 1)},
		{"source_negative", strings.Replace(udpStageTraceTestBody, "53535", "-1", 1)},
		{"source_large", strings.Replace(udpStageTraceTestBody, "53535", "65536", 1)},
		{"source_fraction", strings.Replace(udpStageTraceTestBody, "53535", "1.5", 1)},
		{"source_exponent", strings.Replace(udpStageTraceTestBody, "53535", "1e2", 1)},
		{"source_string", strings.Replace(udpStageTraceTestBody, "53535", `"53535"`, 1)},
		{"destination_domain", strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "example.invalid:3478", 1)},
		{"destination_missing_port", strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "192.0.2.51", 1)},
		{"destination_zero_port", strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "192.0.2.51:0", 1)},
		{"destination_large_port", strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "192.0.2.51:65536", 1)},
		{"destination_zone", strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "[fe80::1%lo0]:3478", 1)},
		{"destination_type", strings.Replace(udpStageTraceTestBody, `"192.0.2.51:3478"`, "123", 1)},
		{"outbound_empty", strings.Replace(udpStageTraceTestBody, strconv.Quote(udpStageTraceTestOutbound), `""`, 1)},
		{"outbound_long", strings.Replace(udpStageTraceTestBody, udpStageTraceTestOutbound, strings.Repeat("x", udptrace.MaxTagBytes+1), 1)},
		{"outbound_long_utf8", strings.Replace(udpStageTraceTestBody, udpStageTraceTestOutbound, strings.Repeat("界", udptrace.MaxTagBytes/3+1), 1)},
		{"outbound_type", strings.Replace(udpStageTraceTestBody, strconv.Quote(udpStageTraceTestOutbound), "true", 1)},
		{"invalid_utf8", strings.Replace(udpStageTraceTestBody, udpStageTraceTestOutbound, string([]byte{0xff}), 1)},
		{"trailing_object", udpStageTraceTestBody + " {}"},
		{"trailing_null", udpStageTraceTestBody + " null"},
		{"trailing_garbage", udpStageTraceTestBody + " !"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(http.MethodPost, test.body, strconv.Quote(before.Generation))
			udpStageTraceTestError(t, udpStageTraceTestDo(env, request), http.StatusBadRequest, ErrBadRequest)
			udpStageTraceTestUnchanged(t, env, before)
		})
	}
}

type udpStageTraceBodySpy struct {
	reader     io.Reader
	onRead     func()
	onClose    func()
	readBytes  int
	readCalls  int
	closeCalls int
}

func (body *udpStageTraceBodySpy) Read(p []byte) (int, error) {
	body.readCalls++
	if body.onRead != nil {
		body.onRead()
	}
	n, err := body.reader.Read(p)
	body.readBytes += n
	return n, err
}

func (body *udpStageTraceBodySpy) Close() error {
	body.closeCalls++
	if body.onClose != nil {
		body.onClose()
	}
	return nil
}

func TestUDPStageTrace_BodyLimitsAndClose(t *testing.T) {
	for _, declaredLength := range []bool{true, false} {
		t.Run(strconv.FormatBool(declaredLength), func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(http.MethodPost, "", strconv.Quote(before.Generation))
			body := &udpStageTraceBodySpy{reader: strings.NewReader(strings.Repeat("x", udpStageTraceMaxBodyBytes+100))}
			request.Body = body
			request.ContentLength = -1
			if declaredLength {
				request.ContentLength = udpStageTraceMaxBodyBytes + 100
			}
			writer := newUDPStageTraceDeadlineRecorder()
			body.onRead = func() {
				require.NotEmpty(t, writer.readDeadlines)
				require.False(t, writer.readDeadlines[0].IsZero())
			}
			body.onClose = func() {
				require.NotEmpty(t, writer.readDeadlines)
				require.False(t, writer.readDeadlines[len(writer.readDeadlines)-1].IsZero())
				require.False(t, writer.readDeadlines[len(writer.readDeadlines)-1].After(time.Now()))
			}
			env.server.httpServer.Handler.ServeHTTP(writer, request)
			udpStageTraceTestError(t, writer, http.StatusRequestEntityTooLarge, ErrBadRequest)
			// Chi's WithContext shallow-copies the request, so its Close bool
			// is not shared with the caller. Check the HTTP/1 close policy at
			// response commit time instead of the caller's original request.
			require.Equal(t, "close", writer.Result().Header.Get("Connection"))
			require.Equal(t, 1, body.closeCalls)
			if declaredLength {
				require.Zero(t, body.readCalls)
			} else {
				require.Equal(t, udpStageTraceMaxBodyBytes+1, body.readBytes)
			}
			udpStageTraceTestUnchanged(t, env, before)
		})
	}

	for _, length := range []int{len(udpStageTraceTestBody), udpStageTraceMaxBodyBytes} {
		t.Run("accepted_"+strconv.Itoa(length), func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			etag := udpStageTraceTestDiscover(t, env)
			body := udpStageTraceTestBody + strings.Repeat(" ", length-len(udpStageTraceTestBody))
			writer := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodPost, body, etag))
			snapshot := udpStageTraceTestSnapshot(t, writer)
			require.Equal(t, udptrace.StateArmed, snapshot.State)
			require.NotEmpty(t, writer.readDeadlines)
			require.NotEmpty(t, writer.writeDeadlines)
			for _, deadline := range append(writer.readDeadlines, writer.writeDeadlines...) {
				require.False(t, deadline.IsZero(), "HTTP deadlines must never be cleared before body close")
			}
		})
	}
}

func TestUDPStageTrace_EmptyBodyMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for _, body := range []string{" ", "{}"} {
			t.Run(method+"/"+strconv.Quote(body), func(t *testing.T) {
				env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
				before, err := env.manager.Snapshot("")
				require.NoError(t, err)
				request := udpStageTraceTestRequest(method, body, strconv.Quote(before.Generation))
				request.ContentLength = -1
				udpStageTraceTestError(t, udpStageTraceTestDo(env, request), http.StatusBadRequest, ErrBadRequest)
				udpStageTraceTestUnchanged(t, env, before)
			})
		}
	}
}

func TestUDPStageTrace_DeadlineSupportRequired(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		t.Run(method+"/unsupported", func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(method, "", strconv.Quote(before.Generation))
			body := &udpStageTraceBodySpy{reader: strings.NewReader(udpStageTraceTestBody)}
			request.Body = body
			writer := httptest.NewRecorder()
			env.server.httpServer.Handler.ServeHTTP(writer, request)
			require.Equal(t, http.StatusServiceUnavailable, writer.Code)
			require.JSONEq(t, `{"message":"Diagnostic unavailable"}`, writer.Body.String())
			require.Zero(t, body.readCalls)
			require.Zero(t, body.closeCalls, "unsupported deadlines must not trigger a potentially draining Close")
			udpStageTraceTestUnchanged(t, env, before)
		})
	}
	for _, kind := range []string{"read", "write"} {
		t.Run(kind+"/failure", func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(http.MethodPost, "", strconv.Quote(before.Generation))
			body := &udpStageTraceBodySpy{reader: strings.NewReader(udpStageTraceTestBody)}
			request.Body = body
			writer := newUDPStageTraceDeadlineRecorder()
			if kind == "read" {
				writer.readErr = errors.New(udpStageTraceTestRawError)
			} else {
				writer.writeErr = errors.New(udpStageTraceTestRawError)
			}
			env.server.httpServer.Handler.ServeHTTP(writer, request)
			udpStageTraceTestError(t, writer, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
			require.Zero(t, body.readCalls)
			udpStageTraceTestUnchanged(t, env, before)
		})
	}
}

type udpStageTraceFailingReader struct {
	err error
}

func (reader udpStageTraceFailingReader) Read([]byte) (int, error) { return 0, reader.err }

func TestUDPStageTrace_BodyReadErrors(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		status  int
		message *HTTPError
	}{
		{"opaque_error", errors.New(udpStageTraceTestRawError), http.StatusBadRequest, ErrBadRequest},
		{"unexpected_eof", io.ErrUnexpectedEOF, http.StatusBadRequest, ErrBadRequest},
		{"deadline", os.ErrDeadlineExceeded, http.StatusRequestTimeout, ErrRequestTimeout},
		{"canceled", context.Canceled, http.StatusRequestTimeout, ErrRequestTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			before, err := env.manager.Snapshot("")
			require.NoError(t, err)
			request := udpStageTraceTestRequest(http.MethodPost, "", strconv.Quote(before.Generation))
			request.Body = io.NopCloser(udpStageTraceFailingReader{err: test.err})
			request.ContentLength = -1
			udpStageTraceTestError(t, udpStageTraceTestDo(env, request), test.status, test.message)
			udpStageTraceTestUnchanged(t, env, before)
		})
	}
}

type udpStageTraceDeadlineBody struct {
	writer *udpStageTraceDeadlineRecorder
	read   bool
}

func (body *udpStageTraceDeadlineBody) Read([]byte) (int, error) {
	body.read = true
	if len(body.writer.readDeadlines) == 0 || body.writer.readDeadlines[0].IsZero() {
		return 0, errors.New("missing in-memory read deadline")
	}
	timer := time.NewTimer(time.Until(body.writer.readDeadlines[0]))
	defer timer.Stop()
	<-timer.C
	return 0, os.ErrDeadlineExceeded
}

func (*udpStageTraceDeadlineBody) Close() error { return nil }

func TestUDPStageTrace_BodyReadDeadlineNotContextOnly(t *testing.T) {
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	before, err := env.manager.Snapshot("")
	require.NoError(t, err)
	request := udpStageTraceTestRequest(http.MethodPost, "", strconv.Quote(before.Generation))
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Millisecond)
	defer cancel()
	request = request.WithContext(ctx)
	writer := newUDPStageTraceDeadlineRecorder()
	body := &udpStageTraceDeadlineBody{writer: writer}
	request.Body = body
	request.ContentLength = -1
	started := time.Now()
	env.server.httpServer.Handler.ServeHTTP(writer, request)
	elapsed := time.Since(started)
	udpStageTraceTestError(t, writer, http.StatusRequestTimeout, ErrRequestTimeout)
	require.True(t, body.read)
	require.GreaterOrEqual(t, elapsed, udpStageTraceReadTimeout-100*time.Millisecond)
	require.Less(t, elapsed, udpStageTraceReadTimeout+3*time.Second)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	udpStageTraceTestUnchanged(t, env, before)
}

func TestUDPStageTrace_ArmSnapshotClearAndRedaction(t *testing.T) {
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	initialETag := udpStageTraceTestDiscover(t, env)
	// The selector is an opaque fake flow; no VMess object, frame, socket, or
	// simulated protocol server is constructed by these tests.
	body := strings.Replace(udpStageTraceTestBody, "192.0.2.51:3478", "[::ffff:192.0.2.51]:3478", 1)
	armedWriter := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodPost, body, initialETag))
	armed := udpStageTraceTestSnapshot(t, armedWriter)
	require.Equal(t, udptrace.StateArmed, armed.State)
	require.NotEqual(t, initialETag, armedWriter.Header().Get("ETag"))
	require.EqualValues(t, udptrace.MaxDuration.Milliseconds(), armed.Budget.DurationMS)
	require.EqualValues(t, 1, armed.Budget.MaxFlows)
	require.EqualValues(t, udptrace.MaxEvents, armed.Budget.MaxEvents)
	require.EqualValues(t, udptrace.PrefixBytes, armed.Budget.PrefixBytes)

	selector := udptrace.Selector{Network: "udp", SourcePort: 53535, Destination: netip.MustParseAddrPort("192.0.2.51:3478"), Outbound: udpStageTraceTestOutbound}
	wrongSelector := selector
	wrongSelector.SourcePort++
	require.Nil(t, env.manager.TryClaim(wrongSelector))
	trace := env.manager.TryClaim(selector)
	require.NotNil(t, trace, "HTTP selector must actually be stored and match its normalized destination")
	require.Nil(t, env.manager.TryClaim(selector), "only one flow may claim an arm")
	trace.Record(udptrace.StageBackendReturn, udptrace.Detail{
		Error:   udptrace.ClassifyError(errors.New(udpStageTraceTestRawError)),
		Backend: udptrace.BackendTransport,
	})
	trace.Record(udptrace.StagePacketWriteReturn, udptrace.Detail{Error: udptrace.ErrorNone, Bytes: 20, HasBytes: true})
	trace.SetHeader(udptrace.HeaderSummary{State: udptrace.HeaderComplete, CapturedBytes: udptrace.PrefixBytes, Decoded: &udptrace.HeaderFields{
		Status: udptrace.HeaderKeep, Length: udptrace.HeaderLengthFour, DataFlag: true,
	}})

	armedETag := armedWriter.Header().Get("ETag")
	readWriter := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", armedETag))
	read := udpStageTraceTestSnapshot(t, readWriter)
	require.Equal(t, udptrace.StateClaimed, read.State)
	require.True(t, read.Claimed)
	require.Equal(t, armed.Generation, read.Generation)
	require.Len(t, read.Events, 3)
	require.Equal(t, udptrace.StageClaimed, read.Events[0].Stage)
	require.Equal(t, udptrace.StageBackendReturn, read.Events[1].Stage)
	require.NotNil(t, read.Events[1].Detail)
	require.Equal(t, udptrace.ErrorOther, read.Events[1].Detail.Error)
	require.Equal(t, udptrace.HeaderComplete, read.Header.State)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(readWriter.Body.Bytes(), &fields))
	allowed := map[string]bool{"state": true, "generation": true, "remaining_ms": true, "budget": true, "claimed": true, "events": true, "header": true, "stopped_reason": true}
	for name := range fields {
		require.Contains(t, allowed, name)
	}
	for _, forbidden := range []string{udpStageTraceTestSecret, udpStageTraceTestOutbound, udpStageTraceTestRawError, "192.0.2.51", "source_port", "destination", "selector", "metadata"} {
		require.NotContains(t, readWriter.Body.String(), forbidden)
	}

	clearedWriter := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodDelete, "", armedETag))
	cleared := udpStageTraceTestSnapshot(t, clearedWriter)
	require.Equal(t, udptrace.StateIdle, cleared.State)
	require.NotEqual(t, read.Generation, cleared.Generation)
	require.False(t, cleared.Claimed)
	require.Empty(t, cleared.Events)
	require.Zero(t, cleared.Header.CapturedBytes)
	require.False(t, trace.Active())
	require.Nil(t, env.manager.TryClaim(selector))
	trace.Record(udptrace.StageClose, udptrace.Detail{Error: udptrace.ErrorOther})
	readBack := udpStageTraceTestSnapshot(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", clearedWriter.Header().Get("ETag"))))
	require.Equal(t, cleared, readBack, "clear must read back empty and old trace writes must stay invalid")
	require.Zero(t, env.network.resets.Load(), "clear must not reset business networking")
	require.Zero(t, env.dns.cleared.Load(), "clear must not clear business DNS")
}

func TestUDPStageTrace_ConflictsAndStaleGenerations(t *testing.T) {
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	initialETag := udpStageTraceTestDiscover(t, env)
	armedWriter := udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, initialETag))
	armed := udpStageTraceTestSnapshot(t, armedWriter)
	armedETag := armedWriter.Header().Get("ETag")
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		request := udpStageTraceTestRequest(method, "", initialETag)
		if method == http.MethodPost {
			request = udpStageTraceTestRequest(method, udpStageTraceTestBody, initialETag)
		}
		udpStageTraceTestError(t, udpStageTraceTestDo(env, request), http.StatusPreconditionFailed, errUDPStageTraceGeneration)
		udpStageTraceTestUnchanged(t, env, armed)
	}
	udpStageTraceTestError(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, armedETag)), http.StatusConflict, errUDPStageTraceConflict)
	udpStageTraceTestUnchanged(t, env, armed)
	udpStageTraceTestSnapshot(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodDelete, "", armedETag)))
	udpStageTraceTestError(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodDelete, "", armedETag)), http.StatusPreconditionFailed, errUDPStageTraceGeneration)

	other := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	udpStageTraceTestError(t, udpStageTraceTestDo(other, udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, initialETag)), http.StatusPreconditionFailed, errUDPStageTraceGeneration)
}

func TestUDPStageTrace_ConstructorFailureDoesNotEnable(t *testing.T) {
	t.Run("missing_traffic", func(t *testing.T) {
		manager, err := udptrace.NewManager()
		require.NoError(t, err)
		t.Cleanup(manager.Close)
		ctx := udptrace.ContextWithManager(service.ContextWithDefaultRegistry(context.Background()), manager)
		_, err = NewServer(ctx, log.NewNOPFactory(), udpStageTraceTestOptions())
		require.Error(t, err)
		snapshot, err := manager.Snapshot("")
		require.NoError(t, err)
		require.Equal(t, udptrace.StateDisabled, snapshot.State)
	})
	for _, lateFailure := range []bool{false, true} {
		t.Run("late_"+strconv.FormatBool(lateFailure), func(t *testing.T) {
			ctx, env := udpStageTraceTestContext(t)
			ctx = udptrace.ContextWithManager(ctx, env.manager)
			options := udpStageTraceTestOptions()
			if lateFailure {
				path := filepath.Join(t.TempDir(), "not-a-directory")
				require.NoError(t, os.WriteFile(path, []byte("synthetic test file"), 0o600))
				_, err := os.ReadDir(path)
				require.Error(t, err)
				require.False(t, os.IsNotExist(err))
				options.ExternalUI = path
			} else {
				options.StoreMode = true
			}
			_, err := NewServer(ctx, log.NewNOPFactory(), options)
			require.Error(t, err)
			snapshot, err := env.manager.Snapshot("")
			require.NoError(t, err)
			require.Equal(t, udptrace.StateDisabled, snapshot.State)
			require.Empty(t, snapshot.Events)
		})
	}
}

func TestUDPStageTrace_DisableCloseAndMethods(t *testing.T) {
	t.Run("manager_disabled", func(t *testing.T) {
		env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
		env.manager.Disable()
		udpStageTraceTestError(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", "")), http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
	})
	t.Run("manager_closed", func(t *testing.T) {
		env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
		env.manager.Close()
		udpStageTraceTestError(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", "")), http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
	})
	t.Run("server_close", func(t *testing.T) {
		env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
		etag := udpStageTraceTestDiscover(t, env)
		udpStageTraceTestSnapshot(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodPost, udpStageTraceTestBody, etag)))
		require.NoError(t, env.server.Close())
		snapshot, err := env.manager.Snapshot("")
		require.NoError(t, err)
		require.Equal(t, udptrace.StateDisabled, snapshot.State)
		udpStageTraceTestError(t, udpStageTraceTestDo(env, udpStageTraceTestRequest(http.MethodGet, "", "")), http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
	})
	for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
			writer := udpStageTraceTestDo(env, udpStageTraceTestRequest(method, "", ""))
			udpStageTraceTestError(t, writer, http.StatusMethodNotAllowed, ErrBadRequest)
			require.Equal(t, "GET, POST, DELETE", writer.Header().Get("Allow"))
		})
	}
}

func TestUDPStageTrace_OtherAPIsKeepExistingAuthentication(t *testing.T) {
	env := newUDPStageTraceTestServer(t, udpStageTraceTestOptions(), true)
	request := httptest.NewRequest(http.MethodGet, "/version", nil)
	writer := httptest.NewRecorder()
	env.server.httpServer.Handler.ServeHTTP(writer, request)
	require.Equal(t, http.StatusUnauthorized, writer.Code)
	request.Header.Set("Authorization", "Bearer "+udpStageTraceTestSecret)
	writer = httptest.NewRecorder()
	env.server.httpServer.Handler.ServeHTTP(writer, request)
	require.Equal(t, http.StatusOK, writer.Code, "other routes must not require diagnostic deadline support")
	require.Empty(t, writer.Header().Get("Connection"))
	require.Empty(t, writer.Header().Get("Cache-Control"))
}
