// Package bridgetest has a fake remote MCP server (Streamable HTTP) and a
// fake OAuth 2.1 authorization server, for the tests of `rover bridge`
// and for trying it by hand (examples/fake-remote). Neither is secure; both
// exist to be talked to by Rover.
package bridgetest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Remote is a fake remote MCP server speaking 2025-11-25 Streamable HTTP
// at /mcp: sessions, JSON or SSE answers, an optional GET stream, and an
// optional bearer check that answers 401 with RFC 9728 resource metadata.
type Remote struct {
	// SSE answers requests with text/event-stream instead of JSON.
	SSE bool
	// GET offers the GET stream (one notification, then held open).
	GET bool
	// Check, if set, validates the bearer token; a request without a
	// valid one gets 401 + WWW-Authenticate resource_metadata.
	Check func(token string) bool
	// AuthServer is the issuer listed in the resource metadata.
	AuthServer string
	// Base is the server's own origin (set after it starts).
	Base string

	mu       sync.Mutex
	sessions map[string]bool
	headers  []http.Header
	bodies   [][]byte
	deleted  int
}

// Tool names the fake serves.
const (
	ToolEcho   = "echo"
	ToolDelete = "delete_file"
	ToolBig    = "big"
)

// Headers returns the headers of every request received so far.
func (r *Remote) Headers() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]http.Header(nil), r.headers...)
}

// Bodies returns the bodies of every POST received so far.
func (r *Remote) Bodies() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.bodies...)
}

// Deleted counts DELETEs that ended a session.
func (r *Remote) Deleted() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted
}

// URL is the MCP endpoint.
func (r *Remote) URL() string { return r.Base + "/mcp" }

func (r *Remote) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/.well-known/oauth-protected-resource" || req.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
		writeJSON(w, http.StatusOK, map[string]any{"resource": r.URL(), "authorization_servers": []string{r.AuthServer}, "scopes_supported": []string{"mcp"}})
		return
	}
	if req.URL.Path != "/mcp" {
		http.NotFound(w, req)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	r.mu.Lock()
	r.headers = append(r.headers, req.Header.Clone())
	if req.Method == http.MethodPost {
		r.bodies = append(r.bodies, body)
	}
	r.mu.Unlock()
	if r.Check != nil && !r.Check(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+r.Base+`/.well-known/oauth-protected-resource", scope="mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch req.Method {
	case http.MethodPost:
		r.post(w, req, body)
	case http.MethodGet:
		r.get(w, req)
	case http.MethodDelete:
		r.mu.Lock()
		if r.sessions[req.Header.Get("Mcp-Session-Id")] {
			delete(r.sessions, req.Header.Get("Mcp-Session-Id"))
			r.deleted++
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type rpc struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

func (r *Remote) post(w http.ResponseWriter, req *http.Request, body []byte) {
	acc := req.Header.Get("Accept")
	if !strings.Contains(acc, "application/json") || !strings.Contains(acc, "text/event-stream") {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	var m rpc
	if err := json.Unmarshal(body, &m); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if m.Method == "initialize" {
		id := newID()
		r.mu.Lock()
		if r.sessions == nil {
			r.sessions = map[string]bool{}
		}
		r.sessions[id] = true
		r.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
	} else if !r.validSession(req.Header.Get("Mcp-Session-Id")) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if m.ID == nil { // a notification or a response
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result(m)})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !r.SSE {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reply)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = fmt.Fprintf(w, "id: p-1\ndata:\n\n")
	_, _ = fmt.Fprintf(w, "event: message\nid: p-2\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n")
	_, _ = fmt.Fprintf(w, "id: p-3\ndata: %s\n\n", reply)
}

func (r *Remote) validSession(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

func result(m rpc) any {
	switch m.Method {
	case "initialize":
		return map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fake-remote", "version": "0"}}
	case "tools/list":
		schema := map[string]any{"type": "object"}
		return map[string]any{"tools": []any{
			map[string]any{"name": ToolEcho, "description": "Echoes text.", "inputSchema": schema},
			map[string]any{"name": ToolDelete, "description": "Deletes a file.", "inputSchema": schema},
			map[string]any{"name": ToolBig, "description": "Returns n bytes.", "inputSchema": schema},
		}}
	case "tools/call":
		text := fmt.Sprint(m.Params.Arguments["text"])
		if m.Params.Name == ToolBig {
			n, _ := m.Params.Arguments["n"].(float64)
			text = strings.Repeat("x", int(n))
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
	}
	return map[string]any{}
}

func (r *Remote) get(w http.ResponseWriter, req *http.Request) {
	if !r.GET {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !r.validSession(req.Header.Get("Mcp-Session-Id")) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = fmt.Fprintf(w, "id: g-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-req.Context().Done()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
