package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/keychain"
)

// Record kinds.
const (
	KindOAuth  = "oauth"
	KindBearer = "bearer"
)

// refreshEarly refreshes a token this long before it expires.
const refreshEarly = time.Minute

// Record is what Rover keeps in the keychain for one bridge (service
// "rover", account = the server name or the configured account). It is
// stored as JSON and never written anywhere else. The refresh token lives
// in its own item, account "<account>/refresh" (refreshAccount): the macOS
// keychain holds about 4 KiB per item, and a rotated refresh token that
// did not fit next to a long access token was lost for good, the server
// having already invalidated the old one (review MEDIUM-2).
//
// Resource is the canonical URL the token was issued for (RFC 8707). A
// token is sent only to a URL equal to it or under it (Covers): a stored
// token for one server can never be attached to a request to another
// (review HIGH-1).
type Record struct {
	Kind          string    `json:"kind"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	Expiry        time.Time `json:"expiry,omitzero"`
	ClientID      string    `json:"client_id,omitempty"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	TokenEndpoint string    `json:"token_endpoint,omitempty"`
	Resource      string    `json:"resource,omitempty"`
}

// refreshAccount is the keychain account of a record's refresh token. "/"
// cannot appear in a bridge name or a configured account (ipc.ValidServerName),
// so it never collides with a record.
func refreshAccount(account string) string { return account + "/refresh" }

// Load reads the record for account: the main item plus, if there is one,
// the refresh token item (which wins over a refresh token stored inline by
// an older Rover).
func Load(k keychain.Keyring, account string) (Record, error) {
	s, err := k.Get(keychain.Service, account)
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal([]byte(s), &r); err != nil || r.AccessToken == "" {
		return Record{}, fmt.Errorf("keychain item rover/%s is not a Rover token record", account)
	}
	switch rt, err := k.Get(keychain.Service, refreshAccount(account)); {
	case err == nil:
		r.RefreshToken = rt
	case !errors.Is(err, keychain.ErrNotFound):
		return Record{}, fmt.Errorf("reading the refresh token for %q: %w", account, err)
	}
	return r, nil
}

// Save stores r for account, refresh token first: if it does not fit, the
// previous record is untouched and the error says so; if it is stored and
// the main item then fails, the new refresh token is already in place and
// the previous access token is still readable, so nothing is silently lost.
func Save(k keychain.Keyring, account string, r Record) error {
	if r.Resource == "" {
		return errors.New("refusing to store a token record that does not say which URL it is for")
	}
	main := r
	main.RefreshToken = ""
	b, err := json.Marshal(main) //nolint:gosec // G117: the record is marshalled only to go into the OS keychain, never to disk or logs
	if err != nil {
		return err
	}
	if r.RefreshToken != "" {
		if err := k.Set(keychain.Service, refreshAccount(account), r.RefreshToken); err != nil {
			return fmt.Errorf("storing the refresh token for %q (the previous record is unchanged): %w", account, err)
		}
	}
	if err := k.Set(keychain.Service, account, string(b)); err != nil {
		return fmt.Errorf("storing the access token for %q: %w", account, err)
	}
	if r.RefreshToken == "" {
		if err := k.Delete(keychain.Service, refreshAccount(account)); err != nil && !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("removing the old refresh token for %q: %w", account, err)
		}
	}
	return nil
}

// ErrResource means the stored token was issued for another server.
var ErrResource = errors.New("the stored token is for a different server")

// Covers reports whether a token issued for resource may be sent to target:
// same scheme, host and port, and target's path equal to resource's or under
// it at a "/" boundary, both in canonical form (RFC 8707). An empty or
// unparsable resource covers nothing.
func Covers(resource, target string) bool {
	r, err := url.Parse(resource)
	if err != nil || r.Scheme == "" || r.Host == "" {
		return false
	}
	t, err := url.Parse(target)
	if err != nil || t.Scheme == "" || t.Host == "" {
		return false
	}
	return coversResource(resource, t)
}

// shownURL is a URL for an error message: scheme, host and path only.
func shownURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "<unparsable url>"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// ErrNoToken means the keychain holds no token for the bridge.
var ErrNoToken = errors.New("no token in the keychain")

// Source is a bridge.TokenSource backed by the keychain. OAuth tokens are
// refreshed shortly before they expire, and once more when the server
// answers 401 (ForceRefresh). URL is where the token will be sent; a record
// that was not issued for it (Covers) is never handed out.
type Source struct {
	Keyring keychain.Keyring
	Account string
	URL     string
	HTTP    *http.Client
	Now     func() time.Time

	mu  sync.Mutex
	rec *Record
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Preflight loads the record and checks it is for URL, without refreshing
// anything: `rover bridge` runs it before it starts, so a token for another
// server is refused before a single request is built.
func (s *Source) Preflight() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// loadLocked reads the record once and refuses one for another server.
func (s *Source) loadLocked() error {
	if s.URL == "" {
		return errors.New("oauth.Source without a URL: refusing to hand out a token")
	}
	if s.rec == nil {
		r, err := Load(s.Keyring, s.Account)
		if errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("%w for %q; run `rover bridge login --name %s`", ErrNoToken, s.Account, s.Account)
		}
		if err != nil {
			return err
		}
		s.rec = &r
	}
	if !Covers(s.rec.Resource, s.URL) {
		return fmt.Errorf("%w: the keychain item rover/%s was issued for %s, not for %s; run `rover bridge login --name %s` for this URL",
			ErrResource, s.Account, shownURL(s.rec.Resource), shownURL(s.URL), s.Account)
	}
	return nil
}

// Token implements bridge.TokenSource.
func (s *Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return "", err
	}
	if s.rec.Kind == KindOAuth && !s.rec.Expiry.IsZero() && !s.now().Add(refreshEarly).Before(s.rec.Expiry) {
		if s.rec.RefreshToken == "" {
			if s.now().Before(s.rec.Expiry) {
				return s.rec.AccessToken, nil
			}
			return "", fmt.Errorf("the token for %q expired and there is no refresh token; run `rover bridge login --name %s`", s.Account, s.Account)
		}
		if err := s.refreshLocked(ctx); err != nil {
			return "", err
		}
	}
	return s.rec.AccessToken, nil
}

// ForceRefresh implements bridge.Refresher.
func (s *Source) ForceRefresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rec == nil || s.rec.Kind != KindOAuth || s.rec.RefreshToken == "" {
		return fmt.Errorf("cannot refresh the token for %q; run `rover bridge login --name %s`", s.Account, s.Account)
	}
	return s.refreshLocked(ctx)
}

func (s *Source) refreshLocked(ctx context.Context) error {
	r := *s.rec
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.RefreshToken}, "resource": {r.Resource}}
	tr, err := tokenRequest(ctx, s.HTTP, r.TokenEndpoint, r.ClientID, r.ClientSecret, form)
	if err != nil {
		return fmt.Errorf("refreshing the token for %q: %w", s.Account, err)
	}
	if err := CheckAudience(tr.AccessToken, tr, r.Resource); err != nil {
		return err
	}
	r.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		r.RefreshToken = tr.RefreshToken // rotated
	}
	r.Expiry = tr.expiry(s.now())
	// The server has already rotated: the new tokens are the only valid
	// ones, so they are kept in memory even if the keychain refused them;
	// the error is still reported, this request fails, and the next login
	// starts clean.
	s.rec = &r
	return Save(s.Keyring, s.Account, r)
}

// tokenResponse is an RFC 6749 §5.1 token response, plus the RFC 8707
// resource or an aud some servers echo.
type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int64           `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	Resource     string          `json:"resource"`
	Aud          json.RawMessage `json:"aud"`
	Error        string          `json:"error"`
}

func (t tokenResponse) expiry(now time.Time) time.Time {
	if t.ExpiresIn <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}

// tokenRequest POSTs form to the token endpoint. Error messages carry the
// OAuth error code only, never a token.
func tokenRequest(ctx context.Context, hc *http.Client, endpoint, clientID, secret string, form url.Values) (tokenResponse, error) {
	if secret == "" {
		form.Set("client_id", clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var tr tokenResponse
	derr := decodeCapped(resp.Body, &tr)
	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("token endpoint: HTTP %d %s", resp.StatusCode, safeCode(tr.Error))
	}
	if derr != nil {
		return tokenResponse{}, fmt.Errorf("token endpoint: %w", derr)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "bearer") {
		return tokenResponse{}, errors.New("token endpoint: no bearer access_token in the response")
	}
	return tr, nil
}

func safeCode(s string) string {
	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return ""
		}
	}
	return s
}

// ErrAudience is an access token that is not for this server.
var ErrAudience = errors.New("the authorization server issued a token for a different audience; refusing it")

// CheckAudience enforces the token audience rule (docs/bridge.md):
//   - a JWT access token's aud (string or array) must contain resource;
//   - otherwise, a resource or aud echoed in the token response must equal it;
//   - an opaque token with no echo is accepted: nothing more can be known
//     client-side, and the server must check it (MCP spec).
func CheckAudience(access string, tr tokenResponse, resource string) error {
	if auds, ok := jwtAudience(access); ok {
		if matchAny(auds, resource) {
			return nil
		}
		return fmt.Errorf("%w (aud %q, want %q)", ErrAudience, auds, resource)
	}
	if tr.Resource != "" && !sameResource(tr.Resource, resource) {
		return fmt.Errorf("%w (resource %q, want %q)", ErrAudience, tr.Resource, resource)
	}
	if auds := audValues(tr.Aud); len(auds) > 0 && !matchAny(auds, resource) {
		return fmt.Errorf("%w (aud %q, want %q)", ErrAudience, auds, resource)
	}
	return nil
}

// jwtAudience returns the aud of a JWT, and false if tok is not a JWT
// with an aud claim. The signature is not checked: Rover is not the
// audience, it only refuses to carry a token that says it is for someone
// else.
func jwtAudience(tok string) ([]string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	a, ok := claims["aud"]
	if !ok {
		return nil, false
	}
	return audValues(a), true
}

func audValues(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func matchAny(auds []string, resource string) bool {
	for _, a := range auds {
		if sameResource(a, resource) {
			return true
		}
	}
	return false
}

func sameResource(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	if ea != nil || eb != nil {
		return a == b
	}
	return Canonical(ua) == Canonical(ub)
}

// maxBearer bounds a static token read from stdin.
const maxBearer = 8 << 10

// SaveBearer stores a static bearer token (`rover bridge login --token -`)
// for the server at rawURL, which is recorded in canonical form so the
// token is only ever sent there. Surrounding whitespace is trimmed;
// anything else that could not be sent in an Authorization header is
// refused.
func SaveBearer(k keychain.Keyring, account, token, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("a bearer token needs the URL of the server it is for")
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxBearer {
		return fmt.Errorf("a bearer token must be 1..%d bytes", maxBearer)
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= 0x20 || token[i] >= 0x7f {
			return errors.New("a bearer token must be visible ASCII with no spaces")
		}
	}
	return Save(k, account, Record{Kind: KindBearer, AccessToken: token, Resource: Canonical(u)})
}
