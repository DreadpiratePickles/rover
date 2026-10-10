package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/DreadpiratePickles/rover/internal/bridge"
	"github.com/DreadpiratePickles/rover/internal/bridge/oauth"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/keychain"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// `rover bridge login --name N [--url URL] [--token -]` (M11). With
// --token - it stores a static bearer token read from stdin (never from
// argv: anything in argv is visible to every process in `ps`). Without it,
// it runs the OAuth 2.1 login in the browser. Either way the URL the token
// is for (from --url or config.yaml's bridges entry; both must agree) is
// recorded with it, and the bridge sends it nowhere else.
func bridgeLogin(args []string) int {
	fs := flag.NewFlagSet("bridge login", flag.ExitOnError)
	name := fs.String("name", "", "the bridge name (the keychain account unless config.yaml sets auth.keychain)")
	rawURL := fs.String("url", "", "the remote MCP endpoint (default: bridges.<name>.url in config.yaml)")
	token := fs.String("token", "", `"-" reads a static bearer token from stdin instead of logging in with OAuth`)
	_ = fs.Parse(args)
	if fs.NArg() != 0 || (*token != "" && *token != "-") {
		errf("bridge login: --token takes only \"-\" (read the token from stdin); a token in argv is visible in ps")
		return 2
	}
	dirs, err := paths.Resolve()
	if err != nil {
		errf("%v", err)
		return 1
	}
	st, err := bridgeConfig(dirs, *name, *rawURL, false)
	if err != nil {
		errf("bridge login: %v", err)
		return 2
	}
	account := *name
	if st.inConfig {
		account = st.cfg.Auth.Keychain
	} else {
		errf("bridge login: %s is not in config.yaml; the token is stored but `rover bridge` uses it only once bridges.%s is configured", st.name, st.name)
	}
	if *token == "-" {
		return storeBearer(st, account)
	}
	pool, err := rootCAs(st)
	if err != nil {
		errf("bridge login: %v", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), oauth.DefaultWait+time.Minute)
	defer cancel()
	rec, err := oauth.Login(ctx, oauth.LoginOptions{Name: st.name, Account: account, URL: st.url,
		HTTP: bridge.NewHTTPClient(bridge.ClientOptions{PQRequired: st.pq, RootCAs: pool}), Keyring: keychain.NewOS(),
		ClientID: st.cfg.Auth.ClientID, Open: openBrowser, Printf: errf})
	if errors.Is(err, oauth.ErrNoAuthNeeded) {
		errf("bridge login: %s answered without asking for a token; nothing to store", st.name)
		return 0
	}
	if err != nil {
		errf("bridge login: %v", err)
		return 1
	}
	exp := "no expiry given"
	if !rec.Expiry.IsZero() {
		exp = "expires " + rec.Expiry.Local().Format(time.RFC3339)
	}
	errf("logged in to %s; tokens are in the keychain (service %s, account %s), %s", st.name, keychain.Service, account, exp)
	return 0
}

func storeBearer(st bridgeSettings, account string) int {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
	if err != nil {
		errf("bridge login: reading the token: %v", err)
		return 1
	}
	if err := oauth.SaveBearer(keychain.NewOS(), account, string(b), st.url); err != nil {
		errf("bridge login: %v", err)
		return 1
	}
	errf("stored a bearer token for %s (%s) in the keychain (service %s, account %s)", st.name, st.url, keychain.Service, account)
	return 0
}

// openBrowser shows the login page with the platform's opener. The URL
// holds no secret (state and the PKCE challenge are useless without the
// verifier, which stays in this process).
func openBrowser(u string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.Command(opener, u).Start() //nolint:gosec // G204: the platform opener with our own authorization URL
}

// probeBridgeTLS handshakes with a bridge's host (no HTTP request) and
// returns the negotiated key exchange group.
func probeBridgeTLS(b config.Bridge) (string, error) {
	u, err := bridge.CheckURL(b.URL, b.PQRequired)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.New("plain http (loopback): no TLS")
	}
	pool, err := rootCAs(bridgeSettings{cfg: b})
	if err != nil {
		return "", err
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	cfg := bridge.TLSConfig(bridge.ClientOptions{PQRequired: b.PQRequired, RootCAs: pool})
	cfg.ServerName = u.Hostname()
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	return bridge.GroupName(conn.ConnectionState().CurveID), nil
}

// checkRemote reports one bridge's negotiated group.
func checkRemote(b config.Bridge, group string, err error) check {
	host := b.URL
	if u, perr := url.Parse(b.URL); perr == nil {
		host = u.Host
	}
	switch {
	case err != nil && b.PQRequired:
		return fail("remote", "%s: %s: handshake failed with pq_required (fails closed): %v", b.Name, host, err)
	case err != nil:
		return fail("remote", "%s: %s: %v", b.Name, host, err)
	case group == "X25519MLKEM768":
		return pass("remote", "%s: %s negotiated %s (post-quantum hybrid)", b.Name, host, group)
	}
	return warn("remote", "%s: %s negotiated %s (classical); set pq_required to refuse it", b.Name, host, group)
}

// remoteChecks runs checkRemote for every bridge in config.yaml.
func remoteChecks(probe func(config.Bridge) (string, error)) []check {
	dirs, err := paths.Resolve()
	if err != nil {
		return []check{fail("remote", "%v", err)}
	}
	cfg, err := config.Load(dirs.Config)
	if err != nil {
		return []check{fail("remote", "%v", err)}
	}
	if len(cfg.Bridges) == 0 {
		return []check{warn("remote", "no bridges in config.yaml (bridges: {name: {url, pq_required, auth}})")}
	}
	var out []check
	for _, n := range cfg.BridgeNames() {
		g, err := probe(cfg.Bridges[n])
		out = append(out, checkRemote(cfg.Bridges[n], g, err))
	}
	return out
}
