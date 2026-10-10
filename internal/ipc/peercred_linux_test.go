package ipc

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var peerHelperSocket = flag.String("ipc-peer-helper", "", "internal: run as the other-user peer for TestRejectsOtherUserViaSudo")

// Exit codes of the helper process.
const (
	helperClosed   = 0 // connected, sent a hello, and the server hung up without a word
	helperDialFail = 2 // could not connect at all
	helperGotData  = 3 // the server answered: the peer check did not work
)

// TestPeerHelper is not a real test: TestRejectsOtherUserViaSudo runs this
// test binary again as user "nobody" with -ipc-peer-helper set, and this
// function plays the part of a hostile local user connecting to roverd.
func TestPeerHelper(*testing.T) {
	if *peerHelperSocket == "" {
		return
	}
	c, err := net.Dial("unix", *peerHelperSocket)
	if err != nil {
		os.Exit(helperDialFail)
	}
	hello, _ := Encode(Message{Type: TypeHello, Hello: &Hello{Version: Version, ClientPID: os.Getppid(), ServerName: "intruder"}})
	_, _ = c.Write(hello)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := c.Read(make([]byte, 64))
	if n > 0 {
		os.Exit(helperGotData)
	}
	os.Exit(helperClosed)
}

// A real second user connects and is rejected by the kernel-reported uid.
// It needs passwordless sudo (CI runners have it; a laptop usually doesn't,
// and then the test skips).
//
// To get past the FIRST lock (file permissions) and test the SECOND (the
// peer check), the test deliberately loosens the socket to 0666 inside a
// 0711 directory.
func TestRejectsOtherUserViaSudo(t *testing.T) {
	if *peerHelperSocket != "" {
		t.Skip("running as the helper")
	}
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo not installed")
	}
	if out, err := exec.Command("sudo", "-n", "-u", "nobody", "true").CombinedOutput(); err != nil {
		t.Skipf("non-interactive sudo to nobody unavailable: %v %s", err, bytes.TrimSpace(out))
	}

	dir, err := os.MkdirTemp("", "rvpeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0o711); err != nil { //nolint:gosec // G302: nobody must traverse this test-only dir; it holds nothing secret
		t.Fatal(err)
	}

	// Copy this test binary where nobody can execute it (go test's own
	// build directory is 0700).
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper")
	if err = copyFile(self, bin); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "s.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err = os.Chmod(sock, 0o666); err != nil { //nolint:gosec // G302: deliberately loosened so the peer check, not file mode, is what stops nobody
		t.Fatal(err)
	}

	g, err := NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 1)
	go func() {
		if c, aerr := g.Accept(l); aerr == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()

	cmd := exec.Command("sudo", "-n", "-u", "nobody", bin, "-test.run=^TestPeerHelper$", "-ipc-peer-helper="+sock) //nolint:gosec // G204: fixed program, test-controlled arguments
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Skipf("could not run helper as nobody: %v", err)
	}
	switch code {
	case helperClosed:
	case helperGotData:
		t.Fatal("the other user got an answer from the server")
	default:
		t.Skipf("helper could not run or connect as nobody (exit %d): %s", code, bytes.TrimSpace(out))
	}
	if g.Rejected() != 1 {
		t.Fatalf("Rejected() = %d, want 1", g.Rejected())
	}
	select {
	case <-accepted:
		t.Fatal("the other user's connection reached the caller")
	default:
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // G304: our own test binary
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755) //nolint:gosec // G302: nobody must be able to execute the helper copy
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
