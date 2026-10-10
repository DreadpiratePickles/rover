package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/state"
)

type failWriter struct{ fail bool }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.fail {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rover-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func start(t *testing.T, o Options) *Server {
	t.Helper()
	if o.SocketPath == "" {
		o.SocketPath = filepath.Join(shortTempDir(t), "d.sock")
	}
	if o.PeerCreds == nil {
		o.PeerCreds = func(*net.UnixConn) (ipc.Creds, error) { return ipc.Creds{UID: 7, PID: 100}, nil }
		o.SelfUID = 7
	}
	if o.ParentPID == nil {
		// Every test wrapper claims pid 100 and the client pid it names.
		o.ParentPID = func(int) (int, error) { return claimedClient, nil }
	}
	s := New(o)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return s
}

// claimedClient is what the injected ParentPID answers; tests that use more
// than one client pid override ParentPID themselves.
var claimedClient = 1

func hello(clientPID int, server string) ipc.Hello {
	return ipc.Hello{WrapperPID: 100, ClientPID: clientPID, ServerName: server, Transport: "stdio"}
}

// parentOf answers ParentPID from a fixed table (wrapper pid -> client pid).
func parentOf(table map[int]int) func(int) (int, error) {
	return func(pid int) (int, error) {
		if p, ok := table[pid]; ok {
			return p, nil
		}
		return 0, errors.New("no such process")
	}
}

func TestDecideForwardsAndLogs(t *testing.T) {
	var log bytes.Buffer
	s := start(t, Options{Audit: audit.New(&log)})
	c, err := ipc.Dial(s.Addr(), hello(1, "fs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"2.0"}}}`)
	v, rel, err := c.Decide("c2s", req)
	if err != nil || v.Action != ipc.ActionForward || rel != nil {
		t.Fatalf("verdict %+v rel %v err %v", v, rel, err)
	}
	v, _, err = c.Decide("s2c", []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if err != nil || v.Action != ipc.ActionForward {
		t.Fatalf("verdict %+v err %v", v, err)
	}

	res := audit.Verify(bytes.NewReader(log.Bytes()))
	if res.Err != nil || res.Entries != 2 {
		t.Fatalf("audit: %+v", res)
	}
	lines := bytes.Split(bytes.TrimSpace(log.Bytes()), []byte("\n"))
	var e0, e1 audit.Entry
	_ = json.Unmarshal(lines[0], &e0)
	_ = json.Unmarshal(lines[1], &e1)
	if e0.Session != c.SessionID() || e0.Server != "fs" || e0.Action != "forward" || e0.Body != nil {
		t.Fatalf("entry 0: %+v", e0)
	}
	if e1.ReplyTo != "initialize" || e1.LatencyMS == nil {
		t.Fatalf("entry 1 not correlated: %+v", e1)
	}
	name, ver := s.Sessions()[0].Client()
	if name != "claude-code" || ver != "2.0" {
		t.Fatalf("clientInfo not recorded: %q %q", name, ver)
	}
}

// Acceptance (M1): two wrappers under the same parent pid share a session.
func TestWrappersWithSameClientPIDShareSession(t *testing.T) {
	// Three wrappers: pids 100 and 101 under agent 42, pid 102 under agent 43.
	pids := []int{100, 101, 102}
	var n int
	s := start(t, Options{
		Audit:     audit.New(&bytes.Buffer{}),
		SelfUID:   7,
		PeerCreds: func(*net.UnixConn) (ipc.Creds, error) { p := pids[n]; n++; return ipc.Creds{UID: 7, PID: p}, nil },
		ParentPID: parentOf(map[int]int{100: 42, 101: 42, 102: 43}),
	})
	a, err := ipc.Dial(s.Addr(), hello(42, "fs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := ipc.Dial(s.Addr(), ipc.Hello{WrapperPID: 101, ClientPID: 42, ServerName: "github", Transport: "stdio"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	other, err := ipc.Dial(s.Addr(), ipc.Hello{WrapperPID: 102, ClientPID: 43, ServerName: "fs", Transport: "stdio"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()

	if a.SessionID() != b.SessionID() {
		t.Fatalf("same client pid, different sessions: %s vs %s", a.SessionID(), b.SessionID())
	}
	if a.SessionID() == other.SessionID() {
		t.Fatal("different client pids must not share a session")
	}
	if n := len(s.Sessions()); n != 2 {
		t.Fatalf("want 2 sessions, got %d", n)
	}
}

func TestSessionEndsWhenLastWrapperLeaves(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{}), SelfUID: 7,
		PeerCreds: func(*net.UnixConn) (ipc.Creds, error) { return ipc.Creds{UID: 7, PID: 100}, nil },
		ParentPID: parentOf(map[int]int{100: 5})})
	a, _ := ipc.Dial(s.Addr(), hello(5, "fs"))
	b, _ := ipc.Dial(s.Addr(), hello(5, "git"))
	_ = a.Close()
	time.Sleep(50 * time.Millisecond)
	if len(s.Sessions()) != 1 {
		t.Fatal("session should survive while one wrapper remains")
	}
	_ = b.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(s.Sessions()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(s.Sessions()) != 0 {
		t.Fatal("session should end when the last wrapper leaves")
	}
}

// Acceptance (M1): a connection from another uid is rejected.
func TestOtherUserIsRefusedBeforeHello(t *testing.T) {
	s := start(t, Options{
		Audit:     audit.New(&bytes.Buffer{}),
		SelfUID:   501,
		PeerCreds: func(*net.UnixConn) (ipc.Creds, error) { return ipc.Creds{UID: 1000, PID: 100}, nil },
	})
	_, err := ipc.Dial(s.Addr(), hello(1, "fs"))
	if err == nil {
		t.Fatal("dial should fail: the daemon must close the socket without a welcome")
	}
}

func TestPeerCredentialErrorIsRefused(t *testing.T) {
	s := start(t, Options{
		Audit:     audit.New(&bytes.Buffer{}),
		PeerCreds: func(*net.UnixConn) (ipc.Creds, error) { return ipc.Creds{}, errors.New("no creds") },
	})
	if _, err := ipc.Dial(s.Addr(), hello(1, "fs")); err == nil {
		t.Fatal("unknown peer must be refused (fail closed)")
	}
}

// A wrapper cannot join another agent's session by naming its pid: the
// kernel's view of the connecting process must agree with the hello.
func TestHelloMustMatchKernelView(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{}), SelfUID: 7,
		PeerCreds: func(*net.UnixConn) (ipc.Creds, error) { return ipc.Creds{UID: 7, PID: 100}, nil },
		ParentPID: parentOf(map[int]int{100: 42})})
	if _, err := ipc.Dial(s.Addr(), ipc.Hello{WrapperPID: 100, ClientPID: 99, ServerName: "fs", Transport: "stdio"}); err == nil || !strings.Contains(err.Error(), "client_pid") {
		t.Fatalf("client_pid lie must be refused with a reason, got %v", err)
	}
	if _, err := ipc.Dial(s.Addr(), ipc.Hello{WrapperPID: 123, ClientPID: 42, ServerName: "fs", Transport: "stdio"}); err == nil || !strings.Contains(err.Error(), "wrapper_pid") {
		t.Fatalf("wrapper_pid lie must be refused with a reason, got %v", err)
	}
	if len(s.Sessions()) != 0 {
		t.Fatal("a refused hello must not create a session")
	}
}

func TestBadHelloGetsErrorFrame(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{})})
	c, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(`{"type":"hello","version":99,"wrapper_pid":1,"client_pid":1,"server_name":"x","transport":"stdio"}` + "\n"))
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), `"type":"error"`) || !strings.Contains(string(buf[:n]), "version") {
		t.Fatalf("want error about version, got %q", buf[:n])
	}
}

// Fail closed: once the audit log cannot be written, every verdict is block.
func TestAuditFailureBlocks(t *testing.T) {
	fw := &failWriter{}
	s := start(t, Options{Audit: audit.New(fw)})
	c, err := ipc.Dial(s.Addr(), hello(1, "fs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if v, _, _ := c.Decide("c2s", msg); v.Action != ipc.ActionForward {
		t.Fatalf("healthy daemon should forward, got %+v", v)
	}
	fw.fail = true
	if v, _, _ := c.Decide("c2s", msg); v.Action != ipc.ActionBlock {
		t.Fatalf("audit failure must block, got %+v", v)
	}
	fw.fail = false
	if v, _, _ := c.Decide("c2s", msg); v.Action != ipc.ActionBlock {
		t.Fatalf("daemon must stay blocked after an audit failure, got %+v", v)
	}
}

func TestSocketIsOwnerOnly(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{})})
	fi, err := os.Stat(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket perm %o, want 600", fi.Mode().Perm())
	}
}

func TestListenRefusesWhenAnotherDaemonAnswers(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{})})
	second := New(Options{SocketPath: s.Addr(), Audit: audit.New(&bytes.Buffer{})})
	if err := second.Listen(); err == nil {
		second.Close()
		t.Fatal("second daemon on a live socket must refuse to start")
	}
}

// Latency budget (plan §4.3): a decide round trip under 10 ms p99.
// TestDecideLatencyBudget is a load-tolerant regression guard for the
// decide round trip. Plan §4.3: "Add a benchmark and fail CI if it goes over
// 10 ms"; the policy-side number is BenchmarkDecide200 in package policy. The
// median must stay under the 10 ms budget; the p99 only under 10x that, so a
// machine busy with fuzzers does not fail it while a real regression still
// does.
func TestDecideLatencyBudget(t *testing.T) {
	src := `@id("echo") permit (principal, action == Action::"call_tool", resource == Tool::"fs/echo");`
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{}), Policy: engine(t, src), Config: enforce()})
	measureDecide(t, s, ipc.ActionForward)
}

// The same budget in observe mode with learn mode recording every call
// into a real state database (M6): decide only queues the observation.
func TestDecideLatencyBudgetWhileLearning(t *testing.T) {
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := observe()
	nc, err := normalize.Parse([]byte("servers:\n  fs:\n    echo: {text: path}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Normalizers = nc
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{}), Policy: engine(t, `@id("none") forbid (principal, action, resource) when { false };`),
		Config: cfg, State: db})
	measureDecide(t, s, ipc.ActionForward) // would_deny, forwarded and recorded
	if obs := dump(t, s); len(obs) != 500 {
		t.Fatalf("%d observations recorded, want 500", len(obs))
	}
}

func measureDecide(t *testing.T, s *Server, want string) {
	t.Helper()
	c, err := ipc.Dial(s.Addr(), hello(1, "fs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"/tmp/x/hi"}}}`)
	const (
		n      = 500
		budget = 10 * time.Millisecond
	)
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		v, _, err := c.Decide("c2s", msg)
		if err != nil || v.Action != want {
			t.Fatalf("verdict %+v err %v", v, err)
		}
		lat = append(lat, time.Since(t0))
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50, p99 := lat[n/2], lat[n*99/100]
	t.Logf("decide p50=%v p99=%v max=%v", p50, p99, lat[n-1])
	if p50 > budget {
		t.Fatalf("p50 %v exceeds the %v budget", p50, budget)
	}
	if p99 > 10*budget {
		t.Fatalf("p99 %v exceeds %v (10x the budget)", p99, 10*budget)
	}
}
