// Package oauth is Rover's own OAuth 2.1 client for remote MCP servers
// (plan M11, MCP authorization spec 2026-07-28; see docs/bridge.md).
//
// LESSON (M11, the confused deputy): a "deputy" is a program that acts with
// someone else's authority. If Rover forwarded whatever token the agent
// handed it, a hostile remote could ask for (and receive) a token meant for
// a different service, and Rover would be the confused deputy that leaked
// it. So Rover is an OAuth client in its own right: it discovers the
// server's authorization server, registers itself, runs the login in the
// user's browser, asks for a token bound to exactly this server (the RFC
// 8707 resource), checks that the token it got is for that server, and keeps
// it in the OS keychain. The agent never sees it, and nothing the agent
// sends becomes a credential.
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/bridge"
)

// maxDoc bounds a metadata document or token response.
const maxDoc = 1 << 20

// ErrNoAuthNeeded means the remote answered without asking for a token.
var ErrNoAuthNeeded = errors.New("the remote server did not ask for authorization (no 401)")

// challenge is the parsed Bearer challenge of a 401.
type challenge struct {
	ResourceMetadata string
	Scope            string
}

// parseChallenge reads resource_metadata and scope from a WWW-Authenticate
// value (RFC 9110 §11.6.1 auth-params, quoted or token values).
func parseChallenge(h string) challenge {
	var c challenge
	i := strings.Index(strings.ToLower(h), "bearer")
	if i < 0 {
		return c
	}
	for _, p := range splitParams(h[i+len("bearer"):]) {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = unquote(strings.TrimSpace(v))
		switch k {
		case "resource_metadata":
			c.ResourceMetadata = v
		case "scope":
			c.Scope = v
		}
	}
	return c
}

// splitParams splits on commas outside quoted strings.
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, esc := false, false
	for _, r := range s {
		switch {
		case esc:
			esc = false
		case inQ && r == '\\':
			esc = true
		case r == '"':
			inQ = !inQ
		case r == ',' && !inQ:
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	return append(out, cur.String())
}

func unquote(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	var b strings.Builder
	esc := false
	for _, r := range v[1 : len(v)-1] {
		if !esc && r == '\\' {
			esc = true
			continue
		}
		esc = false
		b.WriteRune(r)
	}
	return b.String()
}

// prm is RFC 9728 protected resource metadata.
type prm struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// asMeta is RFC 8414 authorization server metadata.
type asMeta struct {
	Issuer                     string   `json:"issuer"`
	AuthorizationEndpoint      string   `json:"authorization_endpoint"`
	TokenEndpoint              string   `json:"token_endpoint"`
	RegistrationEndpoint       string   `json:"registration_endpoint"`
	CodeChallengeMethods       []string `json:"code_challenge_methods_supported"`
	IssParameterSupported      bool     `json:"authorization_response_iss_parameter_supported"`
	TokenEndpointAuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported            []string `json:"scopes_supported"`
	ClientIDMetadataDocSupport bool     `json:"client_id_metadata_document_supported"`
}

// fetchJSON GETs a document from an https (or loopback http) URL into v.
func fetchJSON(ctx context.Context, hc *http.Client, raw string, v any) (int, error) {
	if _, err := bridge.CheckURL(raw, false); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", raw, resp.StatusCode)
	}
	return resp.StatusCode, decodeCapped(resp.Body, v)
}

func decodeCapped(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, maxDoc+1))
	if err != nil {
		return err
	}
	if len(b) > maxDoc {
		return fmt.Errorf("document larger than %d bytes", maxDoc)
	}
	return json.NewDecoder(bytes.NewReader(b)).Decode(v)
}

// probe POSTs an initialize to the server without a token. A 401 gives the
// challenge; a 2xx means no authorization is needed (the session it may
// have opened is ended at once).
func probe(ctx context.Context, hc *http.Client, server string) (challenge, error) {
	body := `{"jsonrpc":"2.0","id":"rover-login","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"rover","version":"login"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, strings.NewReader(body))
	if err != nil {
		return challenge{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return challenge{}, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return parseChallenge(resp.Header.Get("WWW-Authenticate")), nil
	case resp.StatusCode/100 == 2:
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			if del, err := http.NewRequestWithContext(ctx, http.MethodDelete, server, nil); err == nil {
				del.Header.Set("Mcp-Session-Id", sid)
				if r, err := hc.Do(del); err == nil {
					_ = r.Body.Close()
				}
			}
		}
		return challenge{}, ErrNoAuthNeeded
	}
	return challenge{}, nil // no usable challenge: try the well-known URIs
}

// discoverPRM finds the protected resource metadata: the URL from the 401,
// else /.well-known/oauth-protected-resource/<path>, else at the root.
// The document's resource must be this server or a path prefix of it on
// the same origin; otherwise a server could send Rover to log in for a
// different resource.
func discoverPRM(ctx context.Context, hc *http.Client, server *url.URL, c challenge) (prm, error) {
	var cands []string
	if c.ResourceMetadata != "" {
		cands = []string{c.ResourceMetadata}
	} else {
		root := server.Scheme + "://" + server.Host + "/.well-known/oauth-protected-resource"
		if p := strings.Trim(server.EscapedPath(), "/"); p != "" {
			cands = append(cands, root+"/"+p)
		}
		cands = append(cands, root)
	}
	var last error
	for _, cand := range cands {
		var m prm
		if _, err := fetchJSON(ctx, hc, cand, &m); err != nil {
			last = err
			continue
		}
		if len(m.AuthorizationServers) == 0 {
			return prm{}, errors.New("protected resource metadata lists no authorization_servers")
		}
		if !coversResource(m.Resource, server) {
			return prm{}, fmt.Errorf("protected resource metadata is for %q, not %s", m.Resource, Canonical(server))
		}
		return m, nil
	}
	return prm{}, fmt.Errorf("no protected resource metadata: %w", last)
}

func coversResource(resource string, server *url.URL) bool {
	r, err := url.Parse(resource)
	if err != nil || r.Fragment != "" {
		return false
	}
	if !strings.EqualFold(r.Scheme, server.Scheme) || !strings.EqualFold(r.Host, server.Host) {
		return false
	}
	rp, sp := strings.TrimSuffix(r.Path, "/"), strings.TrimSuffix(server.Path, "/")
	return rp == "" || rp == sp || strings.HasPrefix(sp, rp+"/")
}

// Canonical is the RFC 8707 / MCP canonical URI: lower-case scheme and
// host, no fragment, no trailing slash.
func Canonical(u *url.URL) string {
	c := *u
	c.Scheme, c.Host, c.Fragment, c.RawFragment = strings.ToLower(u.Scheme), strings.ToLower(u.Host), "", ""
	c.Path = strings.TrimSuffix(u.Path, "/")
	c.RawPath = ""
	return c.String()
}

// discoverAS fetches RFC 8414 (or OIDC) metadata for issuer, in the order
// the MCP spec gives, and checks issuer equality and PKCE S256 support.
func discoverAS(ctx context.Context, hc *http.Client, issuer string) (asMeta, error) {
	u, err := bridge.CheckURL(issuer, false)
	if err != nil {
		return asMeta{}, fmt.Errorf("authorization server: %w", err)
	}
	origin := u.Scheme + "://" + u.Host
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	cands := []string{origin + "/.well-known/oauth-authorization-server" + p, origin + "/.well-known/openid-configuration" + p}
	if p != "" {
		cands = append(cands, origin+p+"/.well-known/openid-configuration")
	}
	var last error
	for _, cand := range cands {
		var m asMeta
		if _, err := fetchJSON(ctx, hc, cand, &m); err != nil {
			last = err
			continue
		}
		if m.Issuer != issuer {
			return asMeta{}, fmt.Errorf("authorization server metadata at %s names issuer %q, not %q; refusing it", cand, m.Issuer, issuer)
		}
		if !slices.Contains(m.CodeChallengeMethods, "S256") {
			return asMeta{}, errors.New("the authorization server does not advertise PKCE S256; refusing to proceed")
		}
		for _, e := range []string{m.AuthorizationEndpoint, m.TokenEndpoint} {
			if _, err := bridge.CheckURL(e, false); err != nil {
				return asMeta{}, fmt.Errorf("authorization server endpoint: %w", err)
			}
		}
		return m, nil
	}
	return asMeta{}, fmt.Errorf("no authorization server metadata for %s: %w", issuer, last)
}
