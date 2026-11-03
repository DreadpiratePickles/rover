// Package bridge is the remote side of `rover bridge` (plan M11, D10): a
// Streamable HTTP client for one remote MCP server. The client-facing side
// is the same stdio pump as `rover wrap` (internal/proxy), so every message
// still goes through roverd; this package only turns lines into HTTP
// requests and HTTP responses (JSON or SSE) back into lines.
//
// It speaks the transport of MCP 2025-11-25 and 2026-07-28 (docs/bridge.md):
// POST with both Accept types, JSON or SSE answers, Mcp-Session-Id captured
// and replayed, a GET stream for server-initiated messages when offered,
// Last-Event-ID to resume a dropped stream, and DELETE at the end.
package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/rover/internal/framing"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// MaxMessage caps one message from the remote, as for stdio (16 MiB).
const MaxMessage = 16 << 20

// maxErrorBody bounds what is read of an error response for the log.
const maxErrorBody = 4 << 10

// maxSessionID bounds the Mcp-Session-Id Rover will replay.
const maxSessionID = 1024

// TokenSource supplies Rover's own bearer token for the remote ("" for
// none). It never sees anything from the client side.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Refresher is a TokenSource that can refresh after the server said 401.
type Refresher interface {
	ForceRefresh(ctx context.Context) error
}

// Errors the bridge turns into JSON-RPC errors for the client.
var (
	// ErrSessionExpired: 404 to a request that carried a session id.
	ErrSessionExpired = errors.New("the remote ended the MCP session (404); the client must initialize again")
	// ErrTooLarge: one remote message exceeded MaxMessage.
	ErrTooLarge = framing.ErrTooLarge
)

// StatusError is an HTTP status the bridge does not handle.
type StatusError struct {
	Code            int
	WWWAuthenticate string
	Body            string // the start of the body, for the log
}

func (e *StatusError) Error() string {
	if e.Code == http.StatusUnauthorized {
		return "the remote server needs authorization (401); run `rover bridge login`"
	}
	return fmt.Sprintf("remote answered HTTP %d", e.Code)
}

// Transport is the Streamable HTTP client for one remote server.
type Transport struct {
	URL        string
	HTTP       *http.Client
	Auth       TokenSource // nil: no Authorization header at all
	MaxMessage int
	// Logf receives one-line diagnostics (stderr in the binary). It never
	// receives a token.
	Logf func(format string, a ...any)

	mu         sync.Mutex
	session    string
	negotiated string // protocolVersion the server returned from initialize
	requested  string // protocolVersion the client asked for in initialize
	tools      toolTable
}

// New returns a Transport for url using client.
func New(url string, client *http.Client, auth TokenSource) *Transport {
	return &Transport{URL: url, HTTP: client, Auth: auth, MaxMessage: MaxMessage, Logf: func(string, ...any) {}}
}

// Session is the current Mcp-Session-Id ("" if none).
func (t *Transport) Session() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session
}

func (t *Transport) state() (session, negotiated string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session, t.negotiated
}

// version is the protocol version to put in MCP-Protocol-Version after
// initialize: the one the server returned, else the one the client asked
// for (a server that returned none still gets told which version the
// client speaks; the spec wants the header on every later request).
func (t *Transport) version() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.negotiated != "" {
		return t.negotiated
	}
	return t.requested
}

// newRequest builds a request with Rover's own headers and nothing else.
// version, if not empty, is sent as MCP-Protocol-Version (GET and DELETE;
// a POST derives it from its body in setMCPHeaders).
func (t *Transport) newRequest(ctx context.Context, method string, body []byte, version string) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, r)
	if err != nil {
		return nil, err
	}
	if s, _ := t.state(); s != "" {
		req.Header.Set(hdrSession, s)
	}
	if version != "" {
		req.Header.Set(hdrProtocol, version)
	}
	if t.Auth != nil {
		tok, err := t.Auth.Token(ctx)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	return req, nil
}

// do sends a request built by build, and once more after a token refresh
// if the server answers 401 and the token source can refresh.
func (t *Transport) do(ctx context.Context, build func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := t.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		r, ok := t.Auth.(Refresher)
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 || !ok || req.Header.Get("Authorization") == "" {
			return resp, nil
		}
		drain(resp)
		if err := r.ForceRefresh(ctx); err != nil {
			t.Logf("token refresh after 401 failed: %v", err)
			return nil, &StatusError{Code: http.StatusUnauthorized}
		}
	}
}

// Send POSTs one JSON-RPC message (line, with or without its newline) and
// returns the remote's messages in reply, as stdio lines without the
// newline. The channel is closed when the reply is complete. A notification
// or response accepted with 202 yields a closed, empty channel.
func (t *Transport) Send(ctx context.Context, line []byte) (<-chan []byte, error) {
	body := bytes.TrimRight(line, "\r\n")
	m := jsonrpc.Parse(body)
	if m.Kind == jsonrpc.KindRequest && m.Method == "initialize" {
		t.noteRequested(m)
	}
	resp, err := t.do(ctx, func() (*http.Request, error) {
		req, err := t.newRequest(ctx, http.MethodPost, body, "")
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		setMCPHeaders(req.Header, m, t.version())
		for _, kv := range t.paramHeaders(m) {
			req.Header.Set(kv[0], kv[1])
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	sentSession := resp.Request.Header.Get(hdrSession)
	if m.Kind == jsonrpc.KindRequest && m.Method == "initialize" {
		t.captureSession(resp.Header.Get(hdrSession))
	}
	out := make(chan []byte, 8)
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		drain(resp)
		close(out)
		return out, nil
	case resp.StatusCode == http.StatusNotFound && sentSession != "":
		drain(resp)
		t.clearSession(sentSession)
		return nil, ErrSessionExpired
	case resp.StatusCode/100 != 2:
		// A 4xx may carry a JSON-RPC error for this request (e.g. -32020
		// HeaderMismatch); hand that to the client, it explains itself.
		if msg, ok := t.errorReply(resp, m); ok {
			out <- msg
			close(out)
			return out, nil
		}
		return nil, statusError(resp)
	}
	switch mediaType(resp) {
	case "application/json":
		defer drain(resp)
		msg, err := t.readJSON(resp.Body)
		if err != nil {
			return nil, err
		}
		out <- t.noteReply(m, msg)
		close(out)
	case "text/event-stream":
		go t.pumpPOSTStream(ctx, resp, m, out)
	default:
		drain(resp)
		return nil, fmt.Errorf("remote answered with Content-Type %q, want application/json or text/event-stream", resp.Header.Get("Content-Type"))
	}
	return out, nil
}

func (t *Transport) captureSession(id string) {
	if id == "" {
		return
	}
	if len(id) > maxSessionID || !headerSafe(id) || strings.Contains(id, " ") {
		t.Logf("ignoring a malformed Mcp-Session-Id from the remote")
		return
	}
	t.mu.Lock()
	t.session = id
	t.mu.Unlock()
}

func (t *Transport) clearSession(id string) {
	t.mu.Lock()
	if t.session == id {
		t.session = ""
	}
	t.mu.Unlock()
}

// noteReply looks at one message answering req and returns what to forward:
// the reply to initialize fixes the protocol version, and a tools/list
// result teaches the Mcp-Param headers (and loses its invalid tools).
func (t *Transport) noteReply(req jsonrpc.Message, msg []byte) []byte {
	if req.Kind != jsonrpc.KindRequest {
		return msg
	}
	r := jsonrpc.Parse(msg)
	if r.Kind != jsonrpc.KindResult || !bytes.Equal(r.ID, req.ID) {
		return msg
	}
	switch req.Method {
	case "initialize":
		t.noteInitialize(r)
	case "tools/list":
		return t.noteToolsList(req, r)
	}
	return msg
}

// noteRequested records the protocol version the client asked for.
func (t *Transport) noteRequested(req jsonrpc.Message) {
	if v := resultProtocolVersion(req.Params); v != "" {
		t.mu.Lock()
		t.requested = v
		t.mu.Unlock()
	}
}

// noteInitialize records the protocol version from the reply to initialize.
func (t *Transport) noteInitialize(r jsonrpc.Message) {
	if v := resultProtocolVersion(r.Result); v != "" {
		t.mu.Lock()
		t.negotiated = v
		t.mu.Unlock()
	}
}

// readJSON reads one JSON body, capped, as a stdio line.
func (t *Transport) readJSON(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(t.MaxMessage)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > t.MaxMessage {
		return nil, fmt.Errorf("remote message: %w", ErrTooLarge)
	}
	return oneLine(b)
}

// errorReply returns a 4xx JSON body if it is a JSON-RPC error answering req.
func (t *Transport) errorReply(resp *http.Response, req jsonrpc.Message) ([]byte, bool) {
	if req.Kind != jsonrpc.KindRequest || resp.StatusCode/100 != 4 || resp.StatusCode == http.StatusUnauthorized || mediaType(resp) != "application/json" {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
	if err != nil {
		return nil, false
	}
	line, err := oneLine(b)
	if err != nil {
		return nil, false
	}
	r := jsonrpc.Parse(line)
	if r.Kind != jsonrpc.KindError || !bytes.Equal(r.ID, req.ID) {
		return nil, false
	}
	return line, true
}

func statusError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
	return &StatusError{Code: resp.StatusCode, WWWAuthenticate: resp.Header.Get("WWW-Authenticate"), Body: sanitize(string(b))}
}

func mediaType(resp *http.Response) string {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
}

// sanitize keeps printable ASCII for a log line.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= 200 {
			break
		}
	}
	return b.String()
}

// Close ends the session with DELETE (2025-11-25). 405 means the server
// does not allow it, which is fine.
func (t *Transport) Close(ctx context.Context) {
	if t.Session() == "" {
		return
	}
	req, err := t.newRequest(ctx, http.MethodDelete, nil, t.version())
	if err != nil {
		t.Logf("ending the remote session: %v", err)
		return
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		t.Logf("ending the remote session: %v", err)
		return
	}
	drain(resp)
	t.clearSession(req.Header.Get(hdrSession))
}
