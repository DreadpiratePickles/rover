package paths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveHonoursRoverDir(t *testing.T) {
	t.Setenv("ROVER_DIR", "/x/rover")
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if d.Config != "/x/rover/config" || d.State != "/x/rover/state" || d.Run != "/x/rover/run" {
		t.Fatalf("unexpected dirs: %+v", d)
	}
}

func TestEnsureRefusesLooseDirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("ROVER_DIR", base)
	d, _ := Resolve()
	if err := Ensure(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d.State, 0o750); err != nil { //nolint:gosec // G302: the test deliberately loosens the mode
		t.Fatal(err)
	}
	err := Ensure(d)
	if !errors.Is(err, ErrTooOpen) {
		t.Fatalf("want ErrTooOpen, got %v", err)
	}
	if !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("error should tell the user how to fix it: %v", err)
	}
}

func TestSocketPathFallsBackWhenTooLong(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("d", MaxSocketPath))
	d := Dirs{Run: long}
	p, err := SocketPath(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) >= MaxSocketPath {
		t.Fatalf("fallback path still too long: %d bytes", len(p))
	}
	if strings.HasPrefix(p, long) {
		t.Fatalf("expected a fallback outside the long dir, got %s", p)
	}
	fi, err := os.Stat(filepath.Dir(p))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("fallback dir perms: %v %v", fi, err)
	}
}

func TestSocketPathUsesRunDirWhenShort(t *testing.T) {
	d := Dirs{Run: "/tmp/r"}
	p, err := SocketPath(d)
	if err != nil || p != "/tmp/r/roverd.sock" {
		t.Fatalf("got %q %v", p, err)
	}
}
