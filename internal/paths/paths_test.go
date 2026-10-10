package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// clearEnv makes the test independent of the developer's own environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ROVER_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(k, "")
	}
}

// shortTemp returns a short temp directory: t.TempDir() can be too long for a
// socket path on macOS, which is exactly what some tests are about.
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// On macOS /tmp is a symlink to /private/tmp; use the real path so the
	// final component checks below see real directories.
	resolved, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestRoverDirOverride(t *testing.T) {
	clearEnv(t)
	root := shortTemp(t)
	t.Setenv("ROVER_DIR", root)
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := Dirs{
		Config: root,
		State:  filepath.Join(root, "state"),
		Run:    filepath.Join(root, "run"),
		Socket: filepath.Join(root, "run", "roverd.sock"),
	}
	if d != want {
		t.Fatalf("got %+v\nwant %+v", d, want)
	}
}

func TestRoverDirMustBeAbsolute(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROVER_DIR", "relative/dir")
	if _, err := Resolve(); err == nil {
		t.Fatal("relative ROVER_DIR accepted")
	}
}

func TestXDGLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG layout is the Linux default")
	}
	clearEnv(t)
	base := shortTemp(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "st"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(base, "rt"))
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := Dirs{
		Config: filepath.Join(base, "cfg", "rover"),
		State:  filepath.Join(base, "st", "rover"),
		Run:    filepath.Join(base, "rt", "rover"),
		Socket: filepath.Join(base, "rt", "rover", "roverd.sock"),
	}
	if d != want {
		t.Fatalf("got %+v\nwant %+v", d, want)
	}
}

func TestXDGLinuxFallbacks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG layout is the Linux default")
	}
	clearEnv(t)
	base := shortTemp(t)
	t.Setenv("HOME", filepath.Join(base, "home")) // read by os.UserHomeDir/UserConfigDir
	t.Setenv("TMPDIR", filepath.Join(base, "tmp"))
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(base, "tmp", "rover-"+strconv.Itoa(os.Getuid()))
	want := Dirs{
		Config: filepath.Join(base, "home", ".config", "rover"),
		State:  filepath.Join(base, "home", ".local", "state", "rover"),
		Run:    run,
		Socket: filepath.Join(run, "roverd.sock"),
	}
	if d != want {
		t.Fatalf("got %+v\nwant %+v", d, want)
	}
}

func TestRelativeXDGRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG layout is the Linux default")
	}
	for _, k := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
		t.Run(k, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("HOME", shortTemp(t))
			t.Setenv(k, "not/absolute")
			if _, err := Resolve(); err == nil {
				t.Fatalf("relative $%s accepted", k)
			}
		})
	}
}

func TestDarwinLayout(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	clearEnv(t)
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(d.Config, filepath.Join("Library", "Application Support", "Rover")) ||
		d.State != filepath.Join(d.Config, "state") || d.Run != filepath.Join(d.Config, "run") {
		t.Fatalf("unexpected macOS layout: %+v", d)
	}
}

// A long ROVER_DIR would give a socket path the kernel cannot bind; Resolve
// must move the socket to a short private directory in the temp dir.
func TestLongSocketPathFallsBack(t *testing.T) {
	clearEnv(t)
	base := shortTemp(t)
	t.Setenv("TMPDIR", base)
	long := filepath.Join(base, strings.Repeat("a", 120))
	t.Setenv("ROVER_DIR", long)
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "rover-"+strconv.Itoa(os.Getuid()), "roverd.sock")
	if d.Socket != want {
		t.Fatalf("socket = %q, want %q", d.Socket, want)
	}
	if len(d.Socket) > MaxSocketPath {
		t.Fatalf("fallback socket path is %d bytes", len(d.Socket))
	}
	if d.Run != filepath.Join(long, "run") {
		t.Fatalf("run dir moved too: %q", d.Run)
	}
	// Ensure must create (and check) the socket's directory as well.
	if err = d.Ensure(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Dir(d.Socket))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode %o", fi.Mode().Perm())
	}
}

func TestLongSocketPathNoShortFallback(t *testing.T) {
	clearEnv(t)
	base := shortTemp(t)
	t.Setenv("TMPDIR", filepath.Join(base, strings.Repeat("b", 120)))
	t.Setenv("ROVER_DIR", filepath.Join(base, strings.Repeat("a", 120)))
	if _, err := Resolve(); err == nil {
		t.Fatal("expected an error when even the fallback socket path is too long")
	}
}

func resolveIn(t *testing.T, root string) Dirs {
	t.Helper()
	clearEnv(t)
	t.Setenv("ROVER_DIR", root)
	d, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEnsureCreatesPrivateDirs(t *testing.T) {
	d := resolveIn(t, filepath.Join(shortTemp(t), "rover"))
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{d.Config, d.State, d.Run} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode %o, want 700", p, fi.Mode().Perm())
		}
	}
	// Idempotent.
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureRefusesLooseDir(t *testing.T) {
	root := filepath.Join(shortTemp(t), "rover")
	d := resolveIn(t, root)
	if err := os.MkdirAll(d.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d.State, 0o755); err != nil { //nolint:gosec // G302: the test deliberately makes the directory loose
		t.Fatal(err)
	}
	err := d.Ensure()
	if err == nil || !strings.Contains(err.Error(), "0755") {
		t.Fatalf("0755 state dir accepted, err=%v", err)
	}
}

func TestEnsureRefusesSymlinkedDir(t *testing.T) {
	base := shortTemp(t)
	root := filepath.Join(base, "rover")
	d := resolveIn(t, root)
	target := filepath.Join(base, "elsewhere")
	for _, p := range []string{root, target} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// state -> ../elsewhere: a private directory, but reached via a symlink.
	if err := os.Symlink(target, d.State); err != nil {
		t.Fatal(err)
	}
	err := d.Ensure()
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked state dir accepted, err=%v", err)
	}
}

func TestCheckPermsRefusesFile(t *testing.T) {
	root := filepath.Join(shortTemp(t), "rover")
	d := resolveIn(t, root)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.Run, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Ensure(); err == nil {
		t.Fatal("a file where the run dir should be was accepted")
	}
}

func TestEnsureRejectsZeroDirs(t *testing.T) {
	if err := (Dirs{}).Ensure(); err == nil {
		t.Fatal("empty Dirs accepted")
	}
}
