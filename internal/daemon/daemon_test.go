package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/proxy"
)

func needPeerCreds(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are only implemented on linux and darwin")
	}
}

// syncBuf is a bytes.Buffer safe to read while the daemon writes to it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) entries(t *testing.T) []audit.Entry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []audit.Entry
	sc := bufio.NewScanner(bytes.NewReader(s.b.Bytes()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad log line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

type fixture struct {
	d    *Daemon
	path string
	log  *syncBuf
	stop func() error // cancels Serve and returns its error
}

// start runs a daemon on a socket in a short temp dir (macOS limits socket
// paths to about 104 bytes, so t.TempDir() can be too long).
func start(t testing.TB, opts Options) *fixture {
	t.Helper()
	needPeerCreds(t)
	dir, err := os.MkdirTemp("", "rvd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fixture{path: filepath.Join(dir, "roverd.sock"), log: &syncBuf{}}
	if opts.Audit == nil {
		opts.Audit = audit.New(f.log)
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	f.d, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ipc.Listen(f.path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.d.Serve(ctx, l) }()
	var once sync.Once
	var serveErr error
	f.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case serveErr = <-done:
			case <-time.After(10 * time.Second):
				serveErr = errors.New("Serve did not return")
			}
		})
		return serveErr
	}
	t.Cleanup(func() { _ = f.stop() })
	return f
}

func (f *fixture) client(t testing.TB, clientPID int, server string) (*ipc.Client, string) {
	t.Helper()
	c, err := ipc.Dial(f.path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	w, err := c.Hello(ipc.Hello{WrapperPID: os.Getpid(), ClientPID: clientPID, ServerName: server, Transport: "stdio"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, w.SessionID
}

// raw opens a bare connection for sending hand-made lines.
func (f *fixture) raw(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNewRequiresAudit(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without an audit log must fail")
	}
}

// Two wrappers started by the same agent app (same client_pid) share one
// session; a different app gets its own.
func TestSessionSharedByClientPID(t *testing.T) {
	f := start(t, Options{})
	_, a := f.client(t, 1000, "fs")
	_, b := f.client(t, 1000, "git")
	_, c := f.client(t, 2000, "fs")
	if a == "" || a != b {
		t.Fatalf("same client_pid got sessions %q and %q", a, b)
	}
	if c == a {
		t.Fatal("different client_pid shared a session")
	}
	if len(a) != 24 {
		t.Fatalf("session id %q: want 12 random bytes in hex", a)
	}
	if n := len(f.d.Sessions()); n != 2 {
		t.Fatalf("%d sessions, want 2", n)
	}
}

func TestSessionRemovedWhenLastConnectionCloses(t *testing.T) {
	f := start(t, Options{})
	c1, id1 := f.client(t, 1000, "fs")
	c2, _ := f.client(t, 1000, "git")
	_ = c1.Close()
	waitFor(t, "one connection left", func() bool {
		s := f.d.Sessions()
		return len(s) == 1 && s[0].Conns == 1
	})
	_ = c2.Close()
	waitFor(t, "session removed", func() bool { return len(f.d.Sessions()) == 0 })

	// A new wrapper for the same app now starts a NEW session.
	if _, id := f.client(t, 1000, "fs"); id == id1 {
		t.Fatal("session id reused after the session ended")
	}
}

func TestClientInfoAndElicitationFromInitialize(t *testing.T) {
	f := start(t, Options{})
	c, _ := f.client(t, 1000, "fs")
	init := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}},"clientInfo":{"name":"claude-code","version":"2.1.0"}}}`
	if v, err := c.Decide(proxy.ClientToServer, []byte(init)); err != nil || v.Action != proxy.ActionForward {
		t.Fatalf("%+v %v", v, err)
	}
	s := f.d.Sessions()
	if len(s) != 1 || s[0].ClientName != "claude-code" || s[0].ClientVersion != "2.1.0" || !s[0].Elicitation {
		t.Fatalf("session info %+v", s)
	}

	// Without the capability (or with it null), elicitation is false.
	f2 := start(t, Options{})
	c2, _ := f2.client(t, 1000, "fs")
	_, _ = c2.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{"elicitation":null},"clientInfo":{"name":"x"}}}`))
	if s := f2.d.Sessions(); s[0].Elicitation {
		t.Fatal("elicitation: null must not count")
	}
}

// Every decide is logged (with session and server) before the forward verdict.
func TestDecideLogsThenForwards(t *testing.T) {
	clock := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	f := start(t, Options{Now: func() time.Time { return clock }})
	c, sid := f.client(t, 1000, "echo")
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	v, err := c.Decide(proxy.ClientToServer, []byte(req))
	if err != nil || v.Action != proxy.ActionForward || len(v.ReplacementRaw) != 0 {
		t.Fatalf("verdict %+v %v", v, err)
	}
	es := f.log.entries(t)
	if len(es) != 1 {
		t.Fatalf("want 1 entry, got %d", len(es))
	}
	e := es[0]
	if e.Session != sid || e.Server != "echo" || e.Dir != "c2s" || e.Kind != "request" || e.Method != "tools/call" ||
		e.Tool != "echo" || string(e.ID) != "1" || e.Bytes != len(req) || !e.Time.Equal(clock) {
		t.Fatalf("entry %+v", e)
	}
	if e.Body != nil {
		t.Fatal("bodies must be off by default")
	}
	if e.Hash == "" {
		t.Fatal("entry was not chained")
	}
}

func TestLogBodies(t *testing.T) {
	f := start(t, Options{LogBodies: true})
	c, _ := f.client(t, 1000, "echo")
	req := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	if _, err := c.Decide(proxy.ClientToServer, []byte(req)); err != nil {
		t.Fatal(err)
	}
	if es := f.log.entries(t); string(es[0].Body) != req {
		t.Fatalf("body %q", es[0].Body)
	}
}

// On the wire, rule_ids is [] and never null.
func TestVerdictWireFormat(t *testing.T) {
	f := start(t, Options{})
	c := f.raw(t)
	r := bufio.NewReader(c)
	_, _ = c.Write([]byte(`{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1000,"server_name":"s","server_cmd_sha256":"","transport":"stdio"}}` + "\n"))
	welcome, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	m, err := ipc.Decode(welcome)
	if err != nil || m.Welcome == nil {
		t.Fatalf("%s %v", welcome, err)
	}
	_, _ = c.Write([]byte(`{"type":"decide","decide":{"session_id":"` + m.Welcome.SessionID + `","seq":1,"dir":"c2s","raw":{"jsonrpc":"2.0","method":"x"}}}` + "\n"))
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"type":"verdict","verdict":{"seq":1,"action":"forward","rule_ids":[]}}` + "\n"; string(line) != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// If the audit log can't be written: block, reason audit_unavailable, and
// the connection is closed (fail closed).
func TestAuditFailureBlocksAndCloses(t *testing.T) {
	f := start(t, Options{Audit: audit.New(failWriter{})})
	c, _ := f.client(t, 1000, "echo")
	v, err := c.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != proxy.ActionBlock || v.Reason != ReasonAuditUnavailable {
		t.Fatalf("verdict %+v", v)
	}
	if _, err := c.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)); err == nil {
		t.Fatal("connection should be closed after an audit failure")
	}
}

// Every protocol violation closes the connection without a verdict.
func TestProtocolErrorsCloseConnection(t *testing.T) {
	hello := `{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1000,"server_name":"s","server_cmd_sha256":"","transport":"stdio"}}`
	decide := func(sid string, seq, dir string) string {
		return `{"type":"decide","decide":{"session_id":"` + sid + `","seq":` + seq + `,"dir":"` + dir + `","raw":{"jsonrpc":"2.0","method":"x"}}}`
	}
	cases := map[string]struct {
		hello bool // send a valid hello first and expect a welcome
		lines []string
	}{
		"decide before hello":  {false, []string{decide("x", "1", "c2s")}},
		"bad version":          {false, []string{strings.Replace(hello, `"version":1`, `"version":2`, 1)}},
		"no client pid":        {false, []string{strings.Replace(hello, `"client_pid":1000`, `"client_pid":0`, 1)}},
		"garbage":              {false, []string{"GET / HTTP/1.1"}},
		"unknown type":         {true, []string{`{"type":"approve","approve":{}}`}},
		"seq skips":            {true, []string{decide("SID", "2", "c2s")}},
		"seq repeats":          {true, []string{decide("SID", "1", "c2s"), decide("SID", "1", "c2s")}},
		"wrong session":        {true, []string{decide("someone-else", "1", "c2s")}},
		"bad dir":              {true, []string{decide("SID", "1", "sideways")}},
		"verdict from wrapper": {true, []string{`{"type":"verdict","verdict":{"seq":1,"action":"forward","rule_ids":[]}}`}},
		"second hello":         {true, []string{hello}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := start(t, Options{})
			c := f.raw(t)
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			sid := ""
			if tc.hello {
				_, _ = c.Write([]byte(hello + "\n"))
				line, err := r.ReadBytes('\n')
				if err != nil {
					t.Fatal(err)
				}
				m, err := ipc.Decode(line)
				if err != nil || m.Welcome == nil {
					t.Fatalf("%s %v", line, err)
				}
				sid = m.Welcome.SessionID
			}
			var got []string
			for _, l := range tc.lines {
				_, _ = c.Write([]byte(strings.ReplaceAll(l, "SID", sid) + "\n"))
			}
			for {
				line, err := r.ReadBytes('\n')
				if err != nil {
					break
				}
				got = append(got, string(line))
			}
			// "seq repeats" legitimately gets one verdict for its first decide.
			if name == "seq repeats" {
				if len(got) != 1 {
					t.Fatalf("got %q", got)
				}
				return
			}
			if len(got) != 0 {
				t.Fatalf("expected the connection closed with no reply, got %q", got)
			}
		})
	}
}

// A connection whose peer uid is not ours is closed before any hello is read.
func TestRejectsOtherUID(t *testing.T) {
	uid, err := ipc.CurrentUID()
	if err != nil {
		t.Skip(err)
	}
	f := start(t, Options{PeerUID: func(*net.UnixConn) (uint32, error) { return uid + 1, nil }})
	c := f.raw(t)
	_, _ = c.Write([]byte(`{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1000,"server_name":"s","server_cmd_sha256":"","transport":"stdio"}}` + "\n"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read %d bytes from a rejected connection", n)
	}
	waitFor(t, "the rejection to be counted", func() bool { return f.d.Rejected() == 1 })
	if len(f.d.Sessions()) != 0 {
		t.Fatal("a rejected peer created a session")
	}
}

// Cancelling the context stops accepting, closes live connections, removes
// the socket and returns nil.
func TestServeGracefulShutdown(t *testing.T) {
	f := start(t, Options{})
	c, _ := f.client(t, 1000, "echo")
	if err := f.stop(); err != nil {
		t.Fatalf("Serve returned %v", err)
	}
	if _, err := os.Lstat(f.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still there: %v", err)
	}
	if _, err := c.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","method":"x"}`)); err == nil {
		t.Fatal("live connection should be closed")
	}
	if len(f.d.Sessions()) != 0 {
		t.Fatal("sessions should be gone after shutdown")
	}
}

func TestServeTwiceFails(t *testing.T) {
	f := start(t, Options{})
	f.client(t, 1000, "s") // the first Serve is running once this connects
	l, err := ipc.Listen(f.path + "2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := f.d.Serve(context.Background(), l); err == nil {
		t.Fatal("second Serve must fail")
	}
}

// Two wrappers of one session decide concurrently; under -race this checks
// the session registry and the shared audit log.
func TestConcurrentConnections(t *testing.T) {
	f := start(t, Options{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		c, _ := f.client(t, 1000, "s")
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := c.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","method":"x"}`)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if n := len(f.log.entries(t)); n != 400 {
		t.Fatalf("%d entries, want 400", n)
	}
	if _, _, err := audit.Verify(bytes.NewReader(f.log.b.Bytes())); err != nil {
		t.Fatalf("chain broken under concurrency: %v", err)
	}
}

func TestPIDFileIsExclusive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	path := filepath.Join(t.TempDir(), "roverd.pid")
	p, err := AcquirePIDFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AcquirePIDFile(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second acquire: want ErrAlreadyRunning, got %v", err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if strings.TrimSpace(string(b)) != itoa(os.Getpid()) {
		t.Fatalf("pid file holds %q", b)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pid file mode %v", fi.Mode().Perm())
	}
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
	p2, err := AcquirePIDFile(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	_ = p2.Release()
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// The pieces Agent C wires together: a proxy.Pipe whose Decider is an
// ipc.Client talking to a real daemon. Forwarded bytes are exactly the input
// and the audit entry is written.
func TestPipeThroughDaemon(t *testing.T) {
	f := start(t, Options{})
	c, sid := f.client(t, 1000, "echo")
	var toServer, toClient bytes.Buffer
	p := &proxy.Pipe{ToServer: &toServer, ToClient: &toClient, Decider: c}
	in := `{"id":1, "jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"<café>"}}}` + "\n"
	if err := p.Pump(strings.NewReader(in), proxy.ClientToServer); err != nil {
		t.Fatal(err)
	}
	if toServer.String() != in || toClient.Len() != 0 {
		t.Fatalf("toServer=%q toClient=%q", toServer.String(), toClient.String())
	}
	es := f.log.entries(t)
	if len(es) != 1 || es[0].Session != sid || es[0].Tool != "echo" || es[0].Bytes != len(in)-1 {
		t.Fatalf("entries %+v", es)
	}

	// Once roverd is gone, the next message stops the pipe (fail closed).
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	toServer.Reset()
	if err := p.Pump(strings.NewReader(in), proxy.ClientToServer); !errors.Is(err, proxy.ErrStopped) {
		t.Fatalf("want ErrStopped after roverd stopped, got %v", err)
	}
	if toServer.Len() != 0 {
		t.Fatal("forwarded a message with roverd gone")
	}
}

// Ported from A1's proxy.TestFailsClosedWhenAuditFails: if roverd cannot
// write the audit log, the wrapper's pipe forwards nothing, and the session
// stops at the next message (roverd has hung up).
func TestPipeFailsClosedWhenAuditFails(t *testing.T) {
	f := start(t, Options{Audit: audit.New(failWriter{})})
	c, _ := f.client(t, 1000, "echo")
	var toServer, toClient bytes.Buffer
	p := &proxy.Pipe{ToServer: &toServer, ToClient: &toClient, Decider: c}
	in := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	if err := p.Pump(strings.NewReader(in), proxy.ClientToServer); !errors.Is(err, proxy.ErrStopped) {
		t.Fatalf("want ErrStopped, got %v", err)
	}
	if toServer.Len() != 0 || toClient.Len() != 0 {
		t.Fatalf("forwarded without an audit record: toServer=%q toClient=%q", toServer.String(), toClient.String())
	}
}
