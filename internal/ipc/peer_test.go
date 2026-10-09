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
		creds, perr := PeerCreds(ac)
		if perr != nil {
			t.Error(perr)
		}
		if creds.PID != os.Getpid() {
			t.Errorf("peer pid %d, want our own %d", creds.PID, os.Getpid())
		}
		done <- creds.UID
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

func TestParentPIDOfSelfIsOurParent(t *testing.T) {
	ppid, err := ParentPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if ppid != os.Getppid() {
		t.Fatalf("ParentPID(self) = %d, want %d", ppid, os.Getppid())
	}
}

func TestCheckHello(t *testing.T) {
	parent := func(pid int) (int, error) {
		if pid == 10 {
			return 1, nil
		}
		return 0, errors.New("no such process")
	}
	if err := CheckHello(Creds{PID: 10}, 10, 1, parent); err != nil {
		t.Fatalf("honest hello refused: %v", err)
	}
	if err := CheckHello(Creds{PID: 10}, 11, 1, parent); !errors.Is(err, ErrWrongPID) {
		t.Fatalf("wrapper_pid lie accepted: %v", err)
	}
	if err := CheckHello(Creds{PID: 10}, 10, 2, parent); !errors.Is(err, ErrWrongPID) {
		t.Fatalf("client_pid lie accepted: %v", err)
	}
	if err := CheckHello(Creds{PID: 99}, 99, 1, parent); !errors.Is(err, ErrWrongPID) {
		t.Fatalf("unreadable parent must refuse: %v", err)
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
