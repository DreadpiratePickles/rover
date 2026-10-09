package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerUIDIsOurOwnOverLoopbackSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "p.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	done := make(chan uint32, 1)
	go func() {
		ac, aerr := l.AcceptUnix()
		if aerr != nil {
			done <- 0
			return
		}
		defer func() { _ = ac.Close() }()
		uid, perr := PeerUID(ac)
		if perr != nil {
			t.Error(perr)
		}
		done <- uid
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if uid := <-done; uid != uint32(os.Getuid()) { //nolint:gosec // G115: uid fits in uint32 on all supported platforms
		t.Fatalf("peer uid %d, want %d", uid, os.Getuid())
	}
}

func TestCheckPeerRejectsOtherUser(t *testing.T) {
	if err := CheckPeer(1000, 501); !errors.Is(err, ErrWrongUser) {
		t.Fatalf("want ErrWrongUser, got %v", err)
	}
	if err := CheckPeer(501, 501); err != nil {
		t.Fatal(err)
	}
}

// macOS puts t.TempDir() under a long /var/folders path that can exceed the
// 104-byte sun_path limit, so socket tests use a short directory.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rover-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
