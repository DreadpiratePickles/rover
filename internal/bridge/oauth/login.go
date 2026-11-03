package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/bridge"
	"github.com/DreadpiratePickles/rover/internal/keychain"
)

// DefaultWait is how long Login waits for the browser.
const DefaultWait = 5 * time.Minute

// LoginOptions configure one interactive login.
type LoginOptions struct {
	Name     string // the bridge name; the keychain account unless Account is set
	Account  string
	URL      string // the remote MCP endpoint
	HTTP     *http.Client
	Keyring  keychain.Keyring
	ClientID string // a pre-registered client id (config.yaml); empty: register
	// Open shows the authorization URL to the human (open / xdg-open).
	Open func(authURL string) error
	// Printf writes a line for the human (stderr).
	Printf func(format string, a ...any)
	Wait   time.Duration
	Now    func() time.Time
}

// Login runs the OAuth 2.1 authorization code flow with PKCE for one
// remote server and stores the tokens in the keychain.
func Login(ctx context.Context, o LoginOptions) (Record, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Wait == 0 {
		o.Wait = DefaultWait
	}
	account := o.Account
	if account == "" {
		account = o.Name
	}
	server, err := bridge.CheckURL(o.URL, false)
	if err != nil {
		return Record{}, err
	}
	ch, err := probe(ctx, o.HTTP, server.String())
	if err != nil {
		return Record{}, err
	}
	pm, err := discoverPRM(ctx, o.HTTP, server, ch)
	if err != nil {
		return Record{}, err
	}
	resURL, _ := url.Parse(pm.Resource)
	resource := Canonical(resURL)
	issuer := pm.AuthorizationServers[0]
	as, err := discoverAS(ctx, o.HTTP, issuer)
	if err != nil {
		return Record{}, err
	}
	state, verifier := randToken(), randToken()
	lb, err := startLoopback(state)
	if err != nil {
		return Record{}, err
	}
	defer lb.close()
	clientID, secret := o.ClientID, ""
	if clientID == "" {
		if as.RegistrationEndpoint == "" {
			return Record{}, errors.New("the authorization server offers no dynamic registration; set auth.client_id for this bridge in config.yaml")
		}
		if clientID, secret, err = register(ctx, o.HTTP, as.RegistrationEndpoint, lb.RedirectURI()); err != nil {
			return Record{}, err
		}
	}
	authURL, err := authorizationURL(as.AuthorizationEndpoint, clientID, lb.RedirectURI(), verifier, state, resource, scope(ch, pm))
	if err != nil {
		return Record{}, err
	}
	o.Printf("open this URL to log in to %s (Rover tried to open it for you):\n%s", o.Name, authURL)
	if o.Open != nil {
		if oerr := o.Open(authURL); oerr != nil {
			o.Printf("could not open a browser (%v); open the URL above yourself", oerr)
		}
	}
	wctx, cancel := context.WithTimeout(ctx, o.Wait)
	defer cancel()
	cb, err := lb.wait(wctx)
	if err != nil {
		return Record{}, err
	}
	// RFC 9207: an iss that does not match is a mix-up attempt; do not even
	// look at the rest of the response.
	if (cb.iss != "" && cb.iss != as.Issuer) || (cb.iss == "" && as.IssParameterSupported) {
		return Record{}, fmt.Errorf("the authorization response came from issuer %q, not %q; refusing it", cb.iss, as.Issuer)
	}
	if cb.err != nil {
		return Record{}, cb.err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.code}, "redirect_uri": {lb.RedirectURI()},
		"code_verifier": {verifier}, "resource": {resource}}
	tr, err := tokenRequest(ctx, o.HTTP, as.TokenEndpoint, clientID, secret, form)
	if err != nil {
		return Record{}, err
	}
	if err := CheckAudience(tr.AccessToken, tr, resource); err != nil {
		return Record{}, err
	}
	rec := Record{Kind: KindOAuth, AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, Expiry: tr.expiry(o.Now()),
		ClientID: clientID, ClientSecret: secret, Issuer: as.Issuer, TokenEndpoint: as.TokenEndpoint, Resource: resource}
	if err := Save(o.Keyring, account, rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// scope follows the spec's order: the 401's scope, else the resource's
// scopes_supported, else none.
func scope(c challenge, pm prm) string {
	if c.Scope != "" {
		return c.Scope
	}
	return strings.Join(pm.ScopesSupported, " ")
}

// register is RFC 7591 dynamic client registration as a native public client.
func register(ctx context.Context, hc *http.Client, endpoint, redirect string) (string, string, error) {
	if _, err := bridge.CheckURL(endpoint, false); err != nil {
		return "", "", fmt.Errorf("registration endpoint: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"client_name": "Rover", "redirect_uris": []string{redirect}, "application_type": "native",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("dynamic client registration: HTTP %d", resp.StatusCode)
	}
	if err := decodeCapped(resp.Body, &r); err != nil || r.ClientID == "" {
		return "", "", fmt.Errorf("dynamic client registration: no client_id (%v)", err)
	}
	return r.ClientID, r.ClientSecret, nil
}

// authorizationURL adds the authorization request to the endpoint's query.
func authorizationURL(endpoint, clientID, redirect, verifier, state, resource, scope string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", challengeS256(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("resource", resource)
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// challengeS256 is the PKCE S256 code challenge (RFC 7636 §4.2).
func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randToken is 32 random bytes, base64url: a PKCE verifier (43 chars,
// within RFC 7636's 43..128) or a state value.
func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
