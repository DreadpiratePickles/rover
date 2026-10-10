package oauth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/bridge"
	"github.com/DreadpiratePickles/rover/internal/bridge/bridgetest"
	"github.com/DreadpiratePickles/rover/internal/keychain"
)

// world is a fake remote MCP server, its fake authorization server, both
// over TLS, an in-memory keychain and a "browser".
type world struct {
	remote *bridgetest.Remote
	as     *bridgetest.AS
	pool   *x509.CertPool
	hc     *http.Client
	kr     *keychain.Memory
	page   string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{as: &bridgetest.AS{}, kr: keychain.NewMemory(), pool: x509.NewCertPool()}
	asSrv := httptest.NewTLSServer(w.as)
	t.Cleanup(asSrv.Close)
	w.as.Issuer = asSrv.URL
	w.remote = &bridgetest.Remote{AuthServer: asSrv.URL}
	rSrv := httptest.NewTLSServer(w.remote)
	t.Cleanup(rSrv.Close)
	w.remote.Base = rSrv.URL
	w.remote.Check = func(tok string) bool { return w.as.Valid(tok, w.remote.URL()) }
	w.pool.AddCert(asSrv.Certificate())
	w.pool.AddCert(rSrv.Certificate())
	w.hc = bridge.NewHTTPClient(bridge.ClientOptions{RootCAs: w.pool})
	return w
}

// browser follows redirects like a real one, ending on the loopback page.
func (w *world) browser(authURL string) error {
	b := &http.Client{Transport: &http.Transport{TLSClientConfig: bridge.TLSConfig(bridge.ClientOptions{RootCAs: w.pool})}}
	resp, err := b.Get(authURL) //nolint:noctx // test browser
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	w.page = string(body)
	return nil
}

func (w *world) login(t *testing.T) (Record, error) {
	t.Helper()
	return Login(context.Background(), LoginOptions{Name: "fake", URL: w.remote.URL(), HTTP: w.hc, Keyring: w.kr,
		Open: w.browser, Printf: t.Logf, Wait: 10 * time.Second})
}

// Acceptance (M11): the whole flow works against a local OAuth server and a
// fake remote MCP server, tokens end up only in the keychain, and the
// bridge then calls a tool with them.
func TestLoginAndCallEndToEnd(t *testing.T) {
	roverDir, home := t.TempDir(), t.TempDir()
	t.Setenv("ROVER_DIR", roverDir)
	t.Setenv("HOME", home)
	w := newWorld(t)

	rec, err := w.login(t)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindOAuth || rec.RefreshToken == "" || rec.Resource != w.remote.URL() || rec.Issuer != w.as.Issuer {
		t.Fatalf("record: %+v", rec)
	}
	if !strings.Contains(w.page, "you can close this tab") || strings.Contains(strings.ToLower(w.page), "<script") {
		t.Fatalf("loopback page: %q", w.page)
	}
	stored, err := Load(w.kr, "fake")
	if err != nil || stored.AccessToken != rec.AccessToken {
		t.Fatalf("keychain: %v", err)
	}

	src := &Source{Keyring: w.kr, Account: "fake", HTTP: w.hc}
	tr := bridge.New(w.remote.URL(), w.hc, src)
	ch, err := tr.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for range ch {
	}
	ch, err = tr.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"with oauth"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if msg := <-ch; !strings.Contains(string(msg), "with oauth") {
		t.Fatalf("tools/call: %s", msg)
	}

	// Tokens never on disk: nothing under ROVER_DIR or HOME contains them.
	for _, root := range []string{roverDir, home} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p) //nolint:gosec // G304: walking the test's own temp dirs
			for _, tok := range []string{rec.AccessToken, rec.RefreshToken} {
				if strings.Contains(string(b), tok) {
					t.Errorf("token found on disk in %s", p)
				}
			}
			return nil
		})
	}
}

// Acceptance (M11): an authorization server that issues a token for a
// different audience is refused, and nothing is stored.
func TestAudienceMismatchRejected(t *testing.T) {
	w := newWorld(t)
	w.as.Audience = "https://some-other-api.example"
	if _, err := w.login(t); !errors.Is(err, ErrAudience) {
		t.Fatalf("want ErrAudience, got %v", err)
	}
	if _, err := w.kr.Get(keychain.Service, "fake"); !errors.Is(err, keychain.ErrNotFound) {
		t.Fatal("a token with the wrong audience must not be stored")
	}
}

// RFC 9207: a redirect claiming another issuer is a mix-up; refused before
// the code goes anywhere.
func TestIssuerMixUpRejected(t *testing.T) {
	w := newWorld(t)
	w.as.RedirectIss = "https://attacker.example"
	if _, err := w.login(t); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("want an issuer refusal, got %v", err)
	}
	if w.as.Issued != 0 {
		t.Fatal("the code was redeemed despite the issuer mismatch")
	}
}

// Refresh happens before expiry (injected clock) and rotates the refresh token.
func TestRefresh(t *testing.T) {
	w := newWorld(t)
	rec, err := w.login(t)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(2 * time.Hour) // past the 1h expiry
	w.as.Now = func() time.Time { return now }
	src := &Source{Keyring: w.kr, Account: "fake", HTTP: w.hc, Now: func() time.Time { return now }}
	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok == rec.AccessToken || w.as.Refreshed != 1 {
		t.Fatalf("expected a refresh (refreshed %d)", w.as.Refreshed)
	}
	again, _ := Load(w.kr, "fake")
	if again.RefreshToken == rec.RefreshToken || again.AccessToken != tok {
		t.Fatal("the rotated tokens must be saved in the keychain")
	}
}

func TestCheckAudience(t *testing.T) {
	res := "https://mcp.example.com/mcp"
	jwt := func(aud string) string {
		return b64("{}") + "." + b64(`{"aud":`+aud+`}`) + ".sig"
	}
	for _, c := range []struct {
		tok string
		tr  tokenResponse
		ok  bool
	}{
		{jwt(`"https://mcp.example.com/mcp"`), tokenResponse{}, true},
		{jwt(`"HTTPS://MCP.example.com/mcp/"`), tokenResponse{}, true},
		{jwt(`["x","https://mcp.example.com/mcp"]`), tokenResponse{}, true},
		{jwt(`"https://evil.example/mcp"`), tokenResponse{}, false},
		{jwt(`["x"]`), tokenResponse{Resource: res}, false}, // the JWT wins
		{"opaque-token", tokenResponse{}, true},
		{"opaque-token", tokenResponse{Resource: res}, true},
		{"opaque-token", tokenResponse{Resource: "https://evil.example"}, false},
		{"opaque-token", tokenResponse{Aud: []byte(`"https://evil.example"`)}, false},
	} {
		if err := CheckAudience(c.tok, c.tr, res); (err == nil) != c.ok {
			t.Errorf("CheckAudience(%q, %+v) = %v, want ok=%v", c.tok, c.tr, err, c.ok)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	c := parseChallenge(`Bearer error="invalid_token", resource_metadata="https://a.example/.well-known/oauth-protected-resource", scope="files:read files:write"`)
	if c.ResourceMetadata != "https://a.example/.well-known/oauth-protected-resource" || c.Scope != "files:read files:write" {
		t.Fatalf("%+v", c)
	}
	if c := parseChallenge(`Basic realm="x"`); c.ResourceMetadata != "" {
		t.Fatalf("%+v", c)
	}
}

// The loopback page takes one code, only with the right state.
func TestLoopbackOneShot(t *testing.T) {
	lb, err := startLoopback("good-state")
	if err != nil {
		t.Fatal(err)
	}
	defer lb.close()
	get := func(q string) int {
		resp, gerr := http.Get(lb.RedirectURI() + "?" + q) //nolint:noctx // test
		if gerr != nil {
			t.Fatal(gerr)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Error("the page needs a CSP")
		}
		return resp.StatusCode
	}
	if c := get("code=evil&state=guess"); c != http.StatusBadRequest {
		t.Fatalf("wrong state: %d", c)
	}
	if c := get("code=abc&state=good-state"); c != http.StatusOK {
		t.Fatalf("good: %d", c)
	}
	if c := get("code=again&state=good-state"); c != http.StatusGone {
		t.Fatalf("replay: %d", c)
	}
	cb, err := lb.wait(context.Background())
	if err != nil || cb.code != "abc" {
		t.Fatalf("callback %+v %v", cb, err)
	}
}

// An authorization server without PKCE S256 is refused (MCP spec).
func TestRefuseWithoutPKCE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":"http://%s","authorization_endpoint":"http://%s/a","token_endpoint":"http://%s/t"}`, r.Host, r.Host, r.Host) //nolint:gosec // G705: a JSON test fixture, not HTML
	}))
	defer srv.Close()
	if _, err := discoverAS(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("want a PKCE refusal, got %v", err)
	}
}

// An issuer mismatch in the metadata is refused (RFC 8414 §3.3).
func TestRefuseIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"https://honest.example","authorization_endpoint":"https://honest.example/a","token_endpoint":"https://honest.example/t","code_challenge_methods_supported":["S256"]}`)
	}))
	defer srv.Close()
	if _, err := discoverAS(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("want an issuer refusal, got %v", err)
	}
}

func TestBearer(t *testing.T) {
	kr := keychain.NewMemory()
	if err := SaveBearer(kr, "gh", "ghp_abc\n"); err != nil {
		t.Fatal(err)
	}
	src := &Source{Keyring: kr, Account: "gh"}
	if tok, err := src.Token(context.Background()); err != nil || tok != "ghp_abc" {
		t.Fatalf("%q %v", tok, err)
	}
	if err := SaveBearer(kr, "gh", "two words"); err == nil {
		t.Fatal("a token with a space must be refused")
	}
	if _, err := (&Source{Keyring: kr, Account: "none"}).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "rover bridge login") {
		t.Fatalf("missing token: %v", err)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
