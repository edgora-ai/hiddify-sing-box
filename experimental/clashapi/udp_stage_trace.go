package clashapi

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/common/udptrace"
)

const (
	udpStageTracePath          = "/diagnostics/udp-stage"
	udpStageTraceMaxBodyBytes  = 1024
	udpStageTraceReadTimeout   = 2 * time.Second
	udpStageTraceWriteTimeout  = 2 * time.Second
	udpStageTraceMaxGeneration = 128
)

var (
	errUDPStageTraceUnavailable = newError("Diagnostic unavailable")
	errUDPStageTraceConflict    = newError("Diagnostic in use")
	errUDPStageTraceGeneration  = newError("Diagnostic generation changed")
)

func udpStageTraceControllerAllowed(controller, secret string, manager *udptrace.Manager) bool {
	if controller == "" || secret == "" || manager == nil {
		return false
	}
	return udpStageTraceLoopback(controller)
}

func udpStageTraceLoopback(address string) bool {
	addrPort, err := netip.ParseAddrPort(address)
	return err == nil && addrPort.Port() != 0 && addrPort.Addr().Zone() == "" && addrPort.Addr().Unmap().IsLoopback()
}

// This middleware precedes the existing authentication middleware, but only
// affects the exact diagnostic route. Even authentication failures get the
// diagnostic's cache and connection-close policy; other APIs are unchanged.
func udpStageTraceGuard(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != udpStageTracePath {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Connection", "close")
			r.Close = true
			controller := http.NewResponseController(w)
			now := time.Now()
			readErr := controller.SetReadDeadline(now.Add(udpStageTraceReadTimeout))
			writeErr := controller.SetWriteDeadline(now.Add(udpStageTraceReadTimeout + udpStageTraceWriteTimeout))
			// Native HTTP/1 TCP writers support ResponseController deadlines.
			// If a nonstandard writer hides that capability, do not Read or
			// potentially drain via Close. The handler fails closed, but cannot
			// bound that writer/server's later body-finalization behavior.
			if readErr == nil && r.Body != nil {
				defer func() {
					// Close while the HTTP read deadline is still in force. In
					// particular, do not leave an unread body for net/http to
					// drain after its background-read cleanup resets deadlines.
					_ = controller.SetReadDeadline(time.Now())
					_ = r.Body.Close()
				}()
			}

			if r.URL.RawPath != "" {
				udpStageTraceError(w, http.StatusNotFound, ErrNotFound)
				return
			}
			authorization, present, unique := udpStageTraceHeader(r.Header, "Authorization")
			if !present || !unique || subtle.ConstantTimeCompare([]byte(authorization), []byte("Bearer "+secret)) != 1 {
				udpStageTraceError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.RequestURI, "?") || udpStageTraceUpgrade(r.Header) {
				udpStageTraceError(w, http.StatusBadRequest, ErrBadRequest)
				return
			}
			// RemoteAddr is the actual peer. Forwarded/X-Forwarded-* are
			// deliberately neither consulted nor used to relax this check.
			if !udpStageTraceLoopback(r.RemoteAddr) {
				udpStageTraceError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			if readErr != nil || writeErr != nil {
				// A context timeout cannot interrupt a blocking Body.Read.
				// Fail before reading or mutating when real deadlines fail.
				udpStageTraceError(w, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func udpStageTraceHeader(header http.Header, name string) (value string, present, unique bool) {
	for key, values := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		if present || len(values) != 1 {
			return "", true, false
		}
		present = true
		value = values[0]
	}
	return value, present, true
}

func udpStageTraceUpgrade(header http.Header) bool {
	for key, values := range header {
		if strings.EqualFold(key, "Upgrade") {
			return true
		}
		if strings.EqualFold(key, "Connection") {
			for _, value := range values {
				for _, token := range strings.Split(value, ",") {
					if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
						return true
					}
				}
			}
		}
	}
	return false
}

func udpStageTraceHandler(manager *udptrace.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != udpStageTracePath || r.URL.RawPath != "" {
			udpStageTraceError(w, http.StatusNotFound, ErrNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodDelete:
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			udpStageTraceError(w, http.StatusMethodNotAllowed, ErrBadRequest)
			return
		}

		generation, valid := udpStageTraceIfMatch(r.Header, r.Method == http.MethodGet)
		if !valid {
			udpStageTraceError(w, http.StatusBadRequest, ErrBadRequest)
			return
		}
		// Check the selected generation before spending the body-read budget.
		// Arm/Clear check it again atomically when they mutate the manager.
		snapshot, err := manager.Snapshot(generation)
		if err != nil {
			udpStageTraceManagerError(w, err)
			return
		}
		if snapshot.State == udptrace.StateDisabled || snapshot.State == udptrace.StateClosed {
			udpStageTraceError(w, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
			return
		}

		body, status := udpStageTraceReadBody(r)
		if status != 0 {
			message := ErrBadRequest
			if status == http.StatusRequestTimeout {
				message = ErrRequestTimeout
			}
			udpStageTraceError(w, status, message)
			return
		}
		if r.Context().Err() != nil {
			udpStageTraceError(w, http.StatusRequestTimeout, ErrRequestTimeout)
			return
		}

		switch r.Method {
		case http.MethodPost:
			selector, valid := udpStageTraceSelector(body)
			if !valid {
				udpStageTraceError(w, http.StatusBadRequest, ErrBadRequest)
				return
			}
			snapshot, err = manager.Arm(generation, selector)
		case http.MethodGet, http.MethodDelete:
			if len(body) != 0 {
				udpStageTraceError(w, http.StatusBadRequest, ErrBadRequest)
				return
			}
			if r.Method == http.MethodDelete {
				snapshot, err = manager.Clear(generation)
			} else {
				snapshot, err = manager.Snapshot(generation)
			}
		}
		if err != nil {
			udpStageTraceManagerError(w, err)
			return
		}
		udpStageTraceSnapshot(w, snapshot)
	})
}

func udpStageTraceIfMatch(header http.Header, optional bool) (string, bool) {
	value, present, unique := udpStageTraceHeader(header, "If-Match")
	if !present {
		return "", optional
	}
	if !unique || len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	generation := value[1 : len(value)-1]
	return generation, udpStageTraceValidGeneration(generation)
}

func udpStageTraceValidGeneration(generation string) bool {
	if generation == "" || len(generation) > udpStageTraceMaxGeneration {
		return false
	}
	for i := range len(generation) {
		b := generation[i]
		if b < '!' || b > '~' || b == '"' || b == '\\' || b == ',' || b == '*' {
			return false
		}
	}
	return true
}

func udpStageTraceReadBody(r *http.Request) ([]byte, int) {
	if r.ContentLength > udpStageTraceMaxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	if r.Body == nil {
		return nil, 0
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, udpStageTraceMaxBodyBytes+1))
	if len(body) > udpStageTraceMaxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	if err != nil {
		switch udptrace.ClassifyError(err) {
		case udptrace.ErrorDeadline, udptrace.ErrorTimeout, udptrace.ErrorCanceled:
			return nil, http.StatusRequestTimeout
		default:
			return nil, http.StatusBadRequest
		}
	}
	return body, 0
}

func udpStageTraceSelector(body []byte) (udptrace.Selector, bool) {
	var selector udptrace.Selector
	if !utf8.Valid(body) {
		return selector, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return selector, false
	}
	var seen uint8
	var destination string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return selector, false
		}
		var field uint8
		switch token {
		case "source_port":
			field = 1
		case "destination":
			field = 2
		case "outbound":
			field = 4
		default:
			return selector, false
		}
		if seen&field != 0 {
			return selector, false
		}
		seen |= field
		switch field {
		case 1:
			err = decoder.Decode(&selector.SourcePort)
		case 2:
			err = decoder.Decode(&destination)
		case 4:
			err = decoder.Decode(&selector.Outbound)
		}
		if err != nil {
			return selector, false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || seen != 7 {
		return selector, false
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return selector, false
	}
	addrPort, err := netip.ParseAddrPort(destination)
	if err != nil || addrPort.Port() == 0 || addrPort.Addr().Zone() != "" {
		return selector, false
	}
	selector.Network = "udp"
	selector.Destination = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
	return selector, selector.Validate() == nil
}

func udpStageTraceManagerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, udptrace.ErrGeneration):
		udpStageTraceError(w, http.StatusPreconditionFailed, errUDPStageTraceGeneration)
	case errors.Is(err, udptrace.ErrConflict):
		udpStageTraceError(w, http.StatusConflict, errUDPStageTraceConflict)
	case errors.Is(err, udptrace.ErrInvalidSelector):
		udpStageTraceError(w, http.StatusBadRequest, ErrBadRequest)
	default:
		udpStageTraceError(w, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
	}
}

func udpStageTraceSnapshot(w http.ResponseWriter, snapshot udptrace.Snapshot) {
	if snapshot.State == udptrace.StateDisabled || snapshot.State == udptrace.StateClosed {
		udpStageTraceError(w, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
		return
	}
	// Snapshot is the common package's closed, copied output DTO. It has no
	// selector, metadata, raw error, payload, or arbitrary detail string fields.
	body, err := json.Marshal(snapshot)
	if err != nil || len(body)+1 > udptrace.MaxResponseBytes || !udpStageTraceValidGeneration(snapshot.Generation) {
		udpStageTraceError(w, http.StatusServiceUnavailable, errUDPStageTraceUnavailable)
		return
	}
	w.Header().Set("ETag", "\""+snapshot.Generation+"\"")
	udpStageTraceWrite(w, http.StatusOK, body)
}

func udpStageTraceError(w http.ResponseWriter, status int, message *HTTPError) {
	body, err := json.Marshal(message)
	if err != nil || len(body)+1 > udptrace.MaxResponseBytes {
		status = http.StatusServiceUnavailable
		body = []byte(`{"message":"Diagnostic unavailable"}`)
	}
	w.Header().Del("ETag")
	udpStageTraceWrite(w, status, body)
}

func udpStageTraceWrite(w http.ResponseWriter, status int, body []byte) {
	body = append(body, '\n')
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
