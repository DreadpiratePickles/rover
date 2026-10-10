package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Acceptance (M11): pq_required against a server that only does classical
// X25519 fails closed: the handshake fails and the server's handler never
// runs, so not one byte of MCP was sent.
func TestPQRequiredFailsClosed(t *testing.T) {
	var handled atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handled.Add(1) }))
	srv.TLS = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	var groups []string
	hc := NewHTTPClient(ClientOptions{PQRequired: true, RootCAs: pool, OnTLS: func(_, g string) { groups = append(groups, g) }})
	tr := New(srv.URL, hc, staticToken("secret-token"))
	_, err := tr.Send(context.Background(), []byte(initLine))
	if !errors.Is(err, ErrNoPQ) {
		t.Fatalf("want ErrNoPQ, got %v", err)
	}
	if handled.Load() != 0 || len(groups) != 0 {
		t.Fatalf("a request reached the server (%d) or a connection was made (%v)", handled.Load(), groups)
	}

	// Without pq_required the same server works, over classical X25519,
	// and the bridge reports exactly that.
	hc = NewHTTPClient(ClientOptions{RootCAs: pool, OnTLS: func(_, g string) { groups = append(groups, g) }})
	// The handler answers 200 with no body, which Send reports as an
	// error; what matters is that the request arrived.
	_, _ = New(srv.URL, hc, nil).Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if handled.Load() != 1 {
		t.Fatalf("classical send did not arrive (%d)", handled.Load())
	}
	if len(groups) != 1 || groups[0] != "X25519" {
		t.Fatalf("groups %v, want [X25519]", groups)
	}
}

// pq_required against a server that supports the hybrid succeeds.
func TestPQRequiredHybridWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	var groups []string
	hc := NewHTTPClient(ClientOptions{PQRequired: true, RootCAs: pool, OnTLS: func(_, g string) { groups = append(groups, g) }})
	if _, err := New(srv.URL, hc, nil).Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "X25519MLKEM768" {
		t.Fatalf("groups %v", groups)
	}
}

func TestCheckURL(t *testing.T) {
	for _, c := range []struct {
		url string
		pq  bool
		ok  bool
	}{
		{"https://mcp.example.com/mcp", true, true},
		{"http://127.0.0.1:8080/mcp", false, true},
		{"http://localhost/mcp", false, true},
		{"http://127.0.0.1:8080/mcp", true, false},
		{"http://mcp.example.com/mcp", false, false},
		{"https://user:pw@mcp.example.com/", false, false},
		{"https://mcp.example.com/#frag", false, false},
		{"ftp://mcp.example.com/", false, false},
		// Review L-2: one URL must not spell another under Covers.
		{"https://mcp.example.com/mcp/../evil", false, false},
		{"https://mcp.example.com/mcp/%2e%2e/evil", false, false},
		{"https://mcp.example.com/mcp/./x", false, false},
		{"https://mcp.example.com/mcp%2Fx", false, false},
		{"https://mcp.example.com/mcp%2fx", false, false},
		{"https://mcp.example.com/m%63p/..x", false, true},
	} {
		if _, err := CheckURL(c.url, c.pq); (err == nil) != c.ok {
			t.Errorf("CheckURL(%q, pq=%v) = %v", c.url, c.pq, err)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	c := TLSConfig(ClientOptions{PQRequired: true})
	if c.MinVersion != tls.VersionTLS13 || len(c.CurvePreferences) != 1 || c.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("pq config: %+v", c)
	}
	if c := TLSConfig(ClientOptions{}); c.CurvePreferences != nil {
		t.Fatal("without pq_required Go's defaults (hybrid first) apply")
	}
	if GroupName(tls.X25519MLKEM768) != "X25519MLKEM768" || GroupName(tls.CurveID(0xfafa)) == "" {
		t.Fatal("GroupName")
	}
}
