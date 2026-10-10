package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/DreadpiratePickles/rover/internal/bridge"
	"github.com/DreadpiratePickles/rover/internal/bridge/oauth"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/keychain"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// `rover bridge --name N --url URL [--pq-required]` (M11): a stdio MCP
// server toward the client, exactly like `rover wrap`, whose "server" is a
// remote Streamable HTTP endpoint. Every message goes through roverd.

// bridgeSettings is what one bridge run uses, flags and config.yaml merged.
type bridgeSettings struct {
	name, url string
	pq        bool
	cfg       config.Bridge
	inConfig  bool
}

func runBridge(args []string) int {
	if len(args) > 0 && args[0] == "login" {
		return bridgeLogin(args[1:])
	}
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	name := fs.String("name", "", "server name for policy, the audit log and the keychain, [A-Za-z0-9_.-]")
	rawURL := fs.String("url", "", "the remote MCP endpoint (https; http only to 127.0.0.1)")
	pq := fs.Bool("pq-required", false, "offer only the post-quantum hybrid X25519MLKEM768; fail closed otherwise")
	remoteType := fs.String("remote-type", "", "the transport type the client config had (set by rover install; informational)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		usage()
	}
	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		errf("%v", err)
		return 1
	}
	st, err := bridgeConfig(dirs, *name, *rawURL, *pq)
	if err != nil {
		errf("bridge: %v", err)
		return 2
	}
	if *remoteType == "sse" {
		errf("bridge %s: the client config said legacy SSE; using Streamable HTTP", st.name)
	}
	return serveBridge(dirs, st)
}

// bridgeConfig merges the flags with config.yaml's bridges.<name>. The
// config wins where it is stricter: its pq_required cannot be turned off by
// a flag, and a url that differs from the configured one is refused (the
// client config is a file an agent can write; config.yaml is approved).
func bridgeConfig(dirs paths.Dirs, name, rawURL string, pqFlag bool) (bridgeSettings, error) {
	if err := ipc.ValidServerName(name); err != nil {
		return bridgeSettings{}, fmt.Errorf("invalid --name: %w", err)
	}
	cfg, err := config.Load(dirs.Config)
	if err != nil {
		return bridgeSettings{}, err
	}
	st := bridgeSettings{name: name, url: rawURL, pq: pqFlag}
	st.cfg, st.inConfig = cfg.Bridges[name]
	if st.inConfig {
		if rawURL == "" {
			st.url = st.cfg.URL
		} else if !sameURL(rawURL, st.cfg.URL) {
			return bridgeSettings{}, fmt.Errorf("--url %q differs from bridges.%s.url in config.yaml; refusing", rawURL, name)
		}
		st.pq = st.pq || st.cfg.PQRequired
	}
	if st.url == "" {
		return bridgeSettings{}, errors.New("no --url, and no bridges." + name + ".url in config.yaml")
	}
	if _, err := bridge.CheckURL(st.url, st.pq); err != nil {
		return bridgeSettings{}, err
	}
	return st, nil
}

func sameURL(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	return ea == nil && eb == nil && oauth.Canonical(ua) == oauth.Canonical(ub)
}

// rootCAs is the system pool plus config's ca_file, or nil for the system pool.
func rootCAs(st bridgeSettings) (*x509.CertPool, error) {
	if st.cfg.CAFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(st.cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %s holds no PEM certificate", st.cfg.CAFile)
	}
	return pool, nil
}

// tokenSource picks the bridge's credentials: none, a keychain bearer or
// OAuth record (config auth), or, for an unconfigured bridge, whatever
// `rover bridge login` stored under its name, if anything.
func tokenSource(st bridgeSettings, hcOpts bridge.ClientOptions) bridge.TokenSource {
	src := &oauth.Source{Keyring: keychain.NewOS(), Account: st.name, HTTP: bridge.NewHTTPClient(hcOpts)}
	if !st.inConfig {
		return optionalSource{src}
	}
	if st.cfg.Auth.Type == config.AuthNone {
		return nil
	}
	src.Account = st.cfg.Auth.Keychain
	return src
}

// optionalSource sends no Authorization header when the keychain has no
// token for the bridge (or there is no keychain): a server that needs one
// answers 401 and the client is told to run `rover bridge login`.
type optionalSource struct{ s *oauth.Source }

func (o optionalSource) Token(ctx context.Context) (string, error) {
	tok, err := o.s.Token(ctx)
	if errors.Is(err, oauth.ErrNoToken) || errors.Is(err, keychain.ErrNoKeychain) {
		return "", nil
	}
	return tok, err
}

func (o optionalSource) ForceRefresh(ctx context.Context) error { return o.s.ForceRefresh(ctx) }

func serveBridge(dirs paths.Dirs, st bridgeSettings) int {
	hello := ipc.Hello{WrapperPID: os.Getpid(), ClientPID: os.Getppid(), ServerName: st.name,
		ServerCmdSHA: commandDigest([]string{"bridge", st.url, strconv.FormatBool(st.pq)}), Transport: "http"}
	// roverd first: no daemon, no remote traffic (fail closed, as for wrap).
	client, err := connect(dirs, hello)
	if err != nil {
		errf("cannot reach roverd, refusing to bridge %q: %v", st.name, err)
		return 1
	}
	defer func() { _ = client.Close() }()
	pool, err := rootCAs(st)
	if err != nil {
		errf("bridge %s: %v", st.name, err)
		return 1
	}
	opts := bridge.ClientOptions{PQRequired: st.pq, RootCAs: pool, OnTLS: func(host, group string) {
		client.SetTLSGroup(group)
		errf("tls: %s negotiated %s", host, group)
	}}
	t := bridge.New(st.url, bridge.NewHTTPClient(opts), tokenSource(st, bridge.ClientOptions{PQRequired: st.pq, RootCAs: pool}))
	t.Logf = errf
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := bridge.NewConn(ctx, t, errf)
	host := ""
	if u, err := url.Parse(st.url); err == nil {
		host = u.Host
	}
	errf("session %s: bridging %q to %s (pq_required %v)", client.SessionID(), st.name, host, st.pq)

	w := proxy.New(client)
	w.Errf = errf
	toAgent := &proxy.LockedWriter{W: os.Stdout}
	client.SetInjectHandler(func(raw []byte) {
		if err := w.Inject(raw, toAgent); err != nil {
			errf("inject from roverd: %v", err)
		}
	})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		conn.Close() // ends the remote session (DELETE), then the pumps
		_ = os.Stdin.Close()
	}()

	inDone, outDone := make(chan error, 1), make(chan error, 1)
	go func() {
		err := w.Pump(os.Stdin, conn, toAgent, proxy.ClientToServer)
		w.Wait()
		conn.Close() // the client hung up: finish in-flight requests, DELETE
		inDone <- err
	}()
	go func() { outDone <- w.Pump(conn.FromRemote(), toAgent, conn, proxy.ServerToClient) }()

	var pumpErr error
	select {
	case pumpErr = <-outDone:
		go conn.Close()
	case pumpErr = <-inDone:
		if e := <-outDone; pumpErr == nil {
			pumpErr = e
		}
	}
	if pumpErr != nil {
		errf("session ended with error: %v", pumpErr)
		return 1
	}
	return 0
}
