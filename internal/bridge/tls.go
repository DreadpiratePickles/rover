package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LESSON (M11): TLS 1.3 agrees on a key with an ephemeral key exchange. The
// group used for it decides what an eavesdropper who records the traffic
// today needs to read it later. X25519 alone falls to a large quantum
// computer; X25519MLKEM768 combines X25519 with ML-KEM-768 (FIPS 203), so
// the session key stays secret unless both are broken. Go offers the hybrid
// first by default. pq_required removes every other group from the offer,
// so a server (or a middlebox) that cannot do the hybrid makes the
// handshake fail before a single byte of MCP is sent: fail closed, never a
// silent downgrade.

// Timeouts for the remote side. There is no overall request timeout: an
// SSE stream legitimately stays open for a long tool call.
const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	headerTimeout    = 5 * time.Minute
	idleConnTimeout  = 90 * time.Second
)

// ClientOptions configure the HTTP client of one bridge.
type ClientOptions struct {
	// PQRequired offers only X25519MLKEM768.
	PQRequired bool
	// RootCAs replaces the system roots (tests, a private CA); nil keeps them.
	RootCAs *x509.CertPool
	// OnTLS is called with the negotiated group's name after every new TLS
	// connection ("X25519MLKEM768", "X25519", ...).
	OnTLS func(host, group string)
}

// TLSConfig is the client TLS configuration every bridge connection uses.
func TLSConfig(o ClientOptions) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: o.RootCAs, NextProtos: []string{"http/1.1"}}
	if o.PQRequired {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}
	return cfg
}

// GroupName names a key exchange group for logs: "X25519MLKEM768", ...
// Anything outside [A-Za-z0-9_-] is dropped so the name is safe in an audit
// finding.
func GroupName(id tls.CurveID) string {
	var b strings.Builder
	for _, r := range id.String() {
		if r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 || b.Len() > 32 {
		return "unknown"
	}
	return b.String()
}

// NewHTTPClient returns the client for one bridge: TLS 1.3 only, the
// negotiated group reported per connection, no proxy from the environment
// (a proxy would see the bearer token in plaintext for http:// and could be
// set by anything that can set our env), and redirects refused so a 3xx can
// never carry the token to another origin.
func NewHTTPClient(o ClientOptions) *http.Client {
	base := TLSConfig(o)
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: headerTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConnsPerHost:   4,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			cfg := base.Clone()
			cfg.ServerName = host
			c := tls.Client(raw, cfg)
			hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
			defer cancel()
			if err := c.HandshakeContext(hctx); err != nil {
				_ = raw.Close()
				if o.PQRequired {
					return nil, fmt.Errorf("%w: %v", ErrNoPQ, err)
				}
				return nil, err
			}
			if o.OnTLS != nil {
				o.OnTLS(host, GroupName(c.ConnectionState().CurveID))
			}
			return c, nil
		},
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ErrNoPQ wraps a handshake that failed while only X25519MLKEM768 was offered.
var ErrNoPQ = errors.New("pq_required: the server did not agree to X25519MLKEM768; nothing was sent")

// CheckURL accepts https URLs, and http only to a loopback address (a
// local test or development server): a bearer token must never cross a
// network in plaintext. pq_required needs TLS, so it refuses http entirely.
func CheckURL(raw string, pqRequired bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("bad url %q: want scheme://host/path with no user info or fragment", raw)
	}
	if hasDotSegment(u.EscapedPath()) || strings.Contains(strings.ToUpper(u.EscapedPath()), "%2F") {
		return nil, fmt.Errorf("bad url %q: no \".\" or \"..\" segments and no encoded slash in the path", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if pqRequired {
			return nil, errors.New("pq_required needs an https url")
		}
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("refusing plain http to %s: only https, or http to 127.0.0.1/::1/localhost", u.Hostname())
		}
		return u, nil
	}
	return nil, fmt.Errorf("bad url %q: want https", raw)
}

// hasDotSegment reports a "." or ".." path segment, literal or
// percent-encoded, which would let one URL spell another (review L-2).
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		s := strings.ToUpper(seg)
		s = strings.ReplaceAll(s, "%2E", ".")
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
