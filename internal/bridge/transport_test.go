package bridge

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/bridge/bridgetest"
	"github.com/DreadpiratePickles/rover/internal/framing"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// remote starts a fake remote MCP server over TLS and a Transport for it.
func remote(t *testing.T, r *bridgetest.Remote, tok TokenSource, groups *[]string) *Transport {
	t.Helper()
	srv := httptest.NewTLSServer(r)
	t.Cleanup(srv.Close)
	r.Base = srv.URL
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	var mu sync.Mutex
	hc := NewHTTPClient(ClientOptions{RootCAs: pool, OnTLS: func(_, g string) {
		mu.Lock()
		defer mu.Unlock()
		if groups != nil {
			*groups = append(*groups, g)
		}
	}})
	tr := New(r.URL(), hc, tok)
	tr.Logf = t.Logf
	return tr
}

// session drives a Conn like the stdio pumps do and collects replies.
type session struct {
	t  *testing.T
	c  *Conn
	in *bufio.Reader
}

func open(t *testing.T, tr *Transport) *session {
	t.Helper()
	c := NewConn(context.Background(), tr, t.Logf)
	return &session{t: t, c: c, in: bufio.NewReader(c.FromRemote())}
}

func (s *session) send(line string) { _, _ = s.c.Write([]byte(line + "\n")) }

func (s *session) recv() map[string]any {
	s.t.Helper()
	type res struct {
		line []byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		l, err := framing.ReadLine(s.in, MaxMessage+1)
		ch <- res{l, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			s.t.Fatalf("read: %v", r.err)
		}
		var m map[string]any
		if err := json.Unmarshal(r.line, &m); err != nil {
			s.t.Fatalf("bad json %q: %v", r.line, err)
		}
		return m
	case <-time.After(10 * time.Second):
		s.t.Fatal("no message from the remote")
		return nil
	}
}

// recvReply skips notifications and returns the next reply.
func (s *session) recvReply() map[string]any {
	s.t.Helper()
	for {
		if m := s.recv(); m["method"] == nil {
			return m
		}
	}
}

// byMethod finds the headers of the request with this Mcp-Method.
func byMethod(hs []http.Header, method string) http.Header {
	for _, h := range hs {
		if h.Get("Mcp-Method") == method {
			return h
		}
	}
	return http.Header{}
}

const initLine = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

func TestBridgeJSONAndSSE(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			r := &bridgetest.Remote{SSE: sse}
			var groups []string
			tr := remote(t, r, nil, &groups)
			s := open(t, tr)
			s.send(initLine)
			if m := s.recvReply(); m["id"] != float64(1) {
				t.Fatalf("initialize: %v", m)
			}
			sid := tr.Session()
			if sid == "" {
				t.Fatal("no Mcp-Session-Id captured")
			}
			s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"over http"}}}`)
			m := s.recvReply()
			if !strings.Contains(fmt.Sprint(m["result"]), "over http") {
				t.Fatalf("tools/call: %v", m)
			}
			s.c.Close()
			hs := r.Headers()
			if len(hs) < 3 {
				t.Fatalf("remote saw %d requests", len(hs))
			}
			for i, h := range hs[1:] {
				if h.Get("Mcp-Session-Id") != sid {
					t.Errorf("request %d did not replay the session id: %v", i+1, h)
				}
			}
			call := byMethod(hs, "tools/call")
			if call.Get("Accept") != "application/json, text/event-stream" || call.Get("MCP-Protocol-Version") != "2025-11-25" ||
				call.Get("Mcp-Method") != "tools/call" || call.Get("Mcp-Name") != "echo" {
				t.Errorf("tools/call headers: %v", call)
			}
			if r.Deleted() != 1 {
				t.Error("Close must DELETE the session")
			}
			if len(groups) == 0 || groups[0] != "X25519MLKEM768" {
				t.Errorf("negotiated groups %v, want X25519MLKEM768 first", groups)
			}
		})
	}
}

// A GET stream delivers server-initiated messages; 405 just means none.
func TestListen(t *testing.T) {
	r := &bridgetest.Remote{GET: true}
	tr := remote(t, r, nil, nil)
	s := open(t, tr)
	s.send(initLine)
	s.recv()
	if m := s.recv(); m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("GET stream message: %v", m)
	}
	s.c.Close()

	r2 := &bridgetest.Remote{}
	tr2 := remote(t, r2, nil, nil)
	ch := tr2.Listen(context.Background())
	if _, ok := <-ch; ok {
		t.Fatal("405 must close the listen channel")
	}
}

// The 16 MiB cap holds on the remote side, for JSON and SSE answers, and
// the client gets an error reply instead of a hang.
func TestRemoteCap(t *testing.T) {
	for _, sse := range []bool{false, true} {
		r := &bridgetest.Remote{SSE: sse}
		tr := remote(t, r, nil, nil)
		s := open(t, tr)
		s.send(initLine)
		s.recvReply()
		s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"big","arguments":{"n":%d}}}`, MaxMessage+1))
		m := s.recvReply()
		e, _ := m["error"].(map[string]any)
		if m["id"] != float64(3) || e == nil || e["code"] != float64(RemoteErrorCode) {
			t.Fatalf("sse=%v: over-cap answer must become an error reply: %.200v", sse, m)
		}
		s.c.Close()
	}
}

// Confused deputy: the client's own credentials never reach the remote.
// Not from the environment, not from inside a message, not via a header
// injection through a tool name. Only Rover's token is sent.
func TestNoClientCredentialsForwarded(t *testing.T) {
	t.Setenv("AUTHORIZATION", "Bearer client-secret-env")
	t.Setenv("MCP_AUTH_TOKEN", "client-secret-env")
	r := &bridgetest.Remote{}
	tr := remote(t, r, staticToken("rover-own-token"), nil)
	s := open(t, tr)
	s.send(initLine)
	s.recv()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo\r\nAuthorization: Bearer client-secret-name","arguments":{"text":"x"},"_meta":{"authorization":"Bearer client-secret-meta","headers":{"Authorization":"Bearer client-secret-meta"}}}}`)
	s.recv()
	s.c.Close()
	for _, h := range r.Headers() {
		if got := h.Values("Authorization"); len(got) != 1 || got[0] != "Bearer rover-own-token" {
			t.Fatalf("Authorization sent to the remote: %q", got)
		}
		for k, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, "client-secret") {
					t.Fatalf("client credential leaked in header %s: %q", k, v)
				}
			}
		}
	}
	if n := byMethod(r.Headers(), "tools/call").Get("Mcp-Name"); !strings.HasPrefix(n, "=?base64?") {
		t.Fatalf("an unsafe tool name must be base64-encoded, got %q", n)
	}
}

// A 404 to a request with a session id clears it and fails the request.
func TestSessionExpired(t *testing.T) {
	r := &bridgetest.Remote{}
	tr := remote(t, r, nil, nil)
	ctx := context.Background()
	ch, err := tr.Send(ctx, []byte(initLine))
	if err != nil {
		t.Fatal(err)
	}
	for range ch {
	}
	tr.mu.Lock()
	tr.session = "stale"
	tr.mu.Unlock()
	if _, err := tr.Send(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
	if tr.Session() != "" {
		t.Fatal("the expired session id must be dropped")
	}
}

// Redirects are never followed: a 3xx could carry the token elsewhere.
func TestNoRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusTemporaryRedirect))
	defer srv.Close()
	tr := New(srv.URL, NewHTTPClient(ClientOptions{}), staticToken("tok"))
	_, err := tr.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusTemporaryRedirect || hits.Load() != 0 {
		t.Fatalf("redirect: err=%v hits=%d", err, hits.Load())
	}
}
