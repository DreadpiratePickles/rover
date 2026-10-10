package bridgetest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// AS is a fake OAuth 2.1 authorization server: RFC 8414 metadata, RFC 7591
// registration, an authorize endpoint that approves at once (no login
// page) and a token endpoint that checks PKCE S256, the redirect URI and
// the RFC 8707 resource, and issues HMAC-signed JWT access tokens.
type AS struct {
	// Issuer is the AS's origin (set after it starts).
	Issuer string
	// Audience, if set, replaces the aud of every token (the audience
	// mismatch test).
	Audience string
	// RedirectIss, if set, replaces the iss on the redirect (the RFC 9207
	// mix-up test).
	RedirectIss string
	// Lifetime of access tokens (default an hour).
	Lifetime time.Duration
	// Now is the clock (default time.Now).
	Now func() time.Time

	key   []byte
	mu    sync.Mutex
	reg   map[string][]string // client_id -> redirect_uris
	codes map[string]grant
	rts   map[string]grant
	// Issued counts access tokens handed out; Refreshed counts refreshes.
	Issued, Refreshed int
}

type grant struct {
	client, redirect, challenge, resource string
}

func (a *AS) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AS) init() {
	if a.key == nil {
		a.key = randBytes(32)
		a.reg, a.codes, a.rts = map[string][]string{}, map[string]grant{}, map[string]grant{}
	}
}

func (a *AS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.init()
	a.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer": a.Issuer, "authorization_endpoint": a.Issuer + "/authorize", "token_endpoint": a.Issuer + "/token",
			"registration_endpoint": a.Issuer + "/register", "code_challenge_methods_supported": []string{"S256"},
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
			"authorization_response_iss_parameter_supported": true,
		})
	case "/register":
		a.register(w, r)
	case "/authorize":
		a.authorize(w, r)
	case "/token":
		a.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *AS) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	id := newID()
	a.mu.Lock()
	a.reg[id] = req.RedirectURIs
	a.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": id, "client_name": req.ClientName, "redirect_uris": req.RedirectURIs, "token_endpoint_auth_method": "none"})
}

func (a *AS) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	uris, ok := a.reg[q.Get("client_id")]
	a.mu.Unlock()
	redirect := q.Get("redirect_uri")
	if !ok || !slices.Contains(uris, redirect) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("resource") == "" {
		http.Error(w, "need response_type=code, PKCE S256 and resource", http.StatusBadRequest)
		return
	}
	code := newID()
	a.mu.Lock()
	a.codes[code] = grant{client: q.Get("client_id"), redirect: redirect, challenge: q.Get("code_challenge"), resource: q.Get("resource")}
	a.mu.Unlock()
	back, _ := url.Parse(redirect)
	v := back.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	v.Set("iss", a.Issuer)
	if a.RedirectIss != "" {
		v.Set("iss", a.RedirectIss)
	}
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: redirect_uri was checked against the registered list above
}

func (a *AS) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	f := r.PostForm
	a.mu.Lock()
	defer a.mu.Unlock()
	var g grant
	switch f.Get("grant_type") {
	case "authorization_code":
		c, ok := a.codes[f.Get("code")]
		delete(a.codes, f.Get("code")) // one use
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if !ok || c.client != f.Get("client_id") || c.redirect != f.Get("redirect_uri") || c.resource != f.Get("resource") ||
			subtle.ConstantTimeCompare([]byte(want), []byte(c.challenge)) != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		g = c
	case "refresh_token":
		c, ok := a.rts[f.Get("refresh_token")]
		delete(a.rts, f.Get("refresh_token")) // rotation
		if !ok || c.client != f.Get("client_id") || c.resource != f.Get("resource") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		g = c
		a.Refreshed++
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	rt := newID()
	a.rts[rt] = g
	a.Issued++
	life := a.Lifetime
	if life == 0 {
		life = time.Hour
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": a.sign(g, life), "token_type": "Bearer", "expires_in": int(life / time.Second), "refresh_token": rt})
}

func (a *AS) sign(g grant, life time.Duration) string {
	aud := g.resource
	if a.Audience != "" {
		aud = a.Audience
	}
	h := b64(`{"alg":"HS256","typ":"JWT"}`)
	p, _ := json.Marshal(map[string]any{"iss": a.Issuer, "aud": aud, "sub": "test-user", "client_id": g.client, "exp": a.now().Add(life).Unix()})
	msg := h + "." + base64.RawURLEncoding.EncodeToString(p)
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Valid is the resource server's check: signed by this AS, not expired,
// and issued for resource.
func (a *AS) Valid(tok, resource string) bool {
	a.mu.Lock()
	a.init()
	key := a.key
	a.mu.Unlock()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	return json.Unmarshal(raw, &c) == nil && c.Aud == resource && a.now().Unix() < c.Exp
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
