package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// shortDir returns a fresh 0700 directory with a short path: Unix socket
// paths are limited to about 104 bytes on macOS, and t.TempDir() can exceed that.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rvipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(shortDir(t), "s.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func needPeerCreds(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are only implemented on linux and darwin")
	}
}

func TestListenSocketIsOwnerOnly(t *testing.T) {
	_, path := listen(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestListenRemovesStaleSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false) // simulate a crash: the file stays behind
	_ = l.Close()
	if _, serr := os.Lstat(path); serr != nil {
		t.Fatalf("stale socket should exist: %v", serr)
	}
	l2, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = l2.Close()
}

func TestListenRefusesLiveSocket(t *testing.T) {
	_, path := listen(t)
	if _, err := Listen(path); err == nil {
		t.Fatal("a second listener on a live socket must fail")
	}
}

func TestListenRefusesNonSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("must not replace a regular file")
	}
	if b, _ := os.ReadFile(path); string(b) != "precious" { //nolint:gosec // G304: test-created temp file
		t.Fatal("regular file was modified")
	}
}

func TestPeerUIDIsOurs(t *testing.T) {
	needPeerCreds(t)
	l, path := listen(t)
	done := make(chan *net.UnixConn, 1)
	go func() {
		c, _ := l.AcceptUnix()
		done <- c
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	sc := <-done
	if sc == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = sc.Close() }()
	uid, err := PeerUID(sc)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := CurrentUID(); uid != want {
		t.Fatalf("PeerUID = %d, want %d", uid, want)
	}
}

// A peer that is not our user is closed before a single byte is read from
// it and never handed to the caller.
func TestGuardRejectsOtherUID(t *testing.T) {
	l, path := listen(t)
	uid, err := CurrentUID()
	if err != nil {
		t.Skip(err)
	}
	rejectedErr := make(chan error, 1)
	g := &Guard{
		UID:      uid,
		PeerUID:  func(*net.UnixConn) (uint32, error) { return uid + 1, nil },
		OnReject: func(err error) { rejectedErr <- err },
	}
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		if c, aerr := g.Accept(l); aerr == nil {
			accepted <- c
		}
	}()

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	hello, _ := Encode(Message{Type: TypeHello, Hello: &Hello{Version: 1, ClientPID: 1}})
	_, _ = c.Write(hello) // may or may not succeed; the server never reads it

	select {
	case err := <-rejectedErr:
		if !errors.Is(err, ErrPeerRejected) {
			t.Fatalf("reject reason = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not rejected")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("rejected peer read %d bytes; want the connection closed", n)
	}
	if g.Rejected() != 1 {
		t.Fatalf("Rejected() = %d, want 1", g.Rejected())
	}
	select {
	case <-accepted:
		t.Fatal("a rejected connection reached the caller")
	default:
	}
}

// A checker that fails is a rejection, not a pass (fail closed).
func TestGuardRejectsWhenCheckerFails(t *testing.T) {
	g := &Guard{UID: 0, PeerUID: func(*net.UnixConn) (uint32, error) { return 0, errors.New("boom") }}
	if err := g.Check(nil); err == nil {
		t.Fatal("checker error must reject")
	}
	if err := (&Guard{}).Check(nil); err == nil {
		t.Fatal("missing checker must reject")
	}
}

func TestGuardAcceptsSameUser(t *testing.T) {
	needPeerCreds(t)
	l, path := listen(t)
	g, err := NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		c, aerr := g.Accept(l)
		if aerr != nil {
			t.Error(aerr)
		}
		accepted <- c
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if sc := <-accepted; sc == nil {
		t.Fatal("same-user connection was not accepted")
	} else {
		_ = sc.Close()
	}
}

// fakeDaemon accepts one connection and runs fn on it.
func fakeDaemon(t *testing.T, fn func(c *Conn)) string {
	t.Helper()
	l, path := listen(t)
	go func() {
		nc, err := l.AcceptUnix()
		if err != nil {
			return
		}
		c := NewConn(nc)
		defer func() { _ = c.Close() }()
		fn(c)
	}()
	return path
}

func TestClientDecideRoundTrip(t *testing.T) {
	needPeerCreds(t)
	path := fakeDaemon(t, func(c *Conn) {
		if _, err := c.Read(); err != nil {
			return
		}
		_ = c.Write(Message{Type: TypeWelcome, Welcome: &Welcome{SessionID: "sid"}})
		for want := uint64(1); ; want++ {
			m, err := c.Read()
			if err != nil || m.Type == TypeBye {
				return
			}
			d := m.Decide
			if d.SessionID != "sid" || d.Seq != want {
				t.Errorf("decide %d: %+v", want, d)
			}
			_ = c.Write(Message{Type: TypeRelease, Release: &Release{Seq: 99, Action: ActionBlock}})
			v := &Verdict{Seq: d.Seq, Action: ActionForward}
			if d.Dir == DirS2C {
				v = &Verdict{Seq: d.Seq, Action: ActionBlock, Reason: "test", ReplacementRaw: json.RawMessage(`{"x":1}`)}
			}
			_ = c.Write(Message{Type: TypeVerdict, Verdict: v})
		}
	})
	c, err := Dial(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	w, err := c.Hello(Hello{ClientPID: 1, ServerName: "t"}, time.Second)
	if err != nil || w.SessionID != "sid" || c.SessionID() != "sid" {
		t.Fatalf("hello: %+v %v", w, err)
	}
	v, err := c.Decide(proxy.ClientToServer, []byte(`{"jsonrpc":"2.0","method":"x"}`))
	if err != nil || v.Action != ActionForward {
		t.Fatalf("c2s: %+v %v", v, err)
	}
	v, err = c.Decide(proxy.ServerToClient, []byte(`{"jsonrpc":"2.0","method":"y"}`))
	if err != nil || v.Action != ActionBlock || string(v.ReplacementRaw) != `{"x":1}` || v.Reason != "test" {
		t.Fatalf("s2c: %+v %v", v, err)
	}
}

func TestClientDecideBeforeHelloFails(t *testing.T) {
	needPeerCreds(t)
	path := fakeDaemon(t, func(c *Conn) { _, _ = c.Read() })
	c, err := Dial(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Decide(proxy.ClientToServer, []byte(`{}`)); err == nil {
		t.Fatal("decide before hello must fail")
	}
}

// A verdict for the wrong seq, or a daemon that hangs up, is an error, and
// the client stays failed afterwards (fail closed).
func TestClientDecideFailuresPoisonClient(t *testing.T) {
	needPeerCreds(t)
	for name, misbehave := range map[string]func(c *Conn, d *Decide){
		"wrong seq": func(c *Conn, d *Decide) {
			_ = c.Write(Message{Type: TypeVerdict, Verdict: &Verdict{Seq: d.Seq + 1, Action: ActionForward}})
		},
		"hang up":         func(c *Conn, _ *Decide) { _ = c.Close() },
		"unexpected type": func(c *Conn, _ *Decide) { _ = c.Write(Message{Type: TypeWelcome, Welcome: &Welcome{SessionID: "x"}}) },
		"garbage": func(c *Conn, _ *Decide) {
			_, _ = c.nc.Write([]byte("not json\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := fakeDaemon(t, func(c *Conn) {
				if _, err := c.Read(); err != nil {
					return
				}
				_ = c.Write(Message{Type: TypeWelcome, Welcome: &Welcome{SessionID: "sid"}})
				m, err := c.Read()
				if err != nil {
					return
				}
				misbehave(c, m.Decide)
				_, _ = c.Read()
			})
			c, err := Dial(path, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Hello(Hello{ClientPID: 1}, time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Decide(proxy.ClientToServer, []byte(`{}`)); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := c.Decide(proxy.ClientToServer, []byte(`{}`)); err == nil {
				t.Fatal("client must stay failed")
			}
		})
	}
}

func TestClientDecideTimeout(t *testing.T) {
	needPeerCreds(t)
	path := fakeDaemon(t, func(c *Conn) {
		if _, err := c.Read(); err != nil {
			return
		}
		_ = c.Write(Message{Type: TypeWelcome, Welcome: &Welcome{SessionID: "sid"}})
		_, _ = io.Copy(io.Discard, c.r) // read decides, never answer
	})
	c, err := Dial(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Hello(Hello{ClientPID: 1}, time.Second); err != nil {
		t.Fatal(err)
	}
	c.DecideTimeout = 100 * time.Millisecond
	start := time.Now()
	if _, err := c.Decide(proxy.ClientToServer, []byte(`{}`)); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not honoured")
	}
}
