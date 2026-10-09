// Package paths decides where Rover keeps its files and checks that nobody
// else can read them.
//
// Layout (plan §4.2):
//
//	macOS  ~/Library/Application Support/Rover/{config,state,run}
//	Linux  $XDG_CONFIG_HOME/rover, $XDG_STATE_HOME/rover, $XDG_RUNTIME_DIR/rover
//
// ROVER_DIR overrides everything with a single base directory. Tests use it;
// so can anyone who wants Rover's files in one place.
//
// Every directory is 0700 and every file 0600. Looser permissions are not
// "fixed up" silently: a world-readable audit log or socket is a security
// failure, so Ensure refuses to run until the owner has looked at it.
package paths

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Dirs is the resolved set of directories for this user.
type Dirs struct {
	Config string // policy files
	State  string // bbolt database, audit log, daemon log
	Run    string // socket and lock files
}

// MaxSocketPath is the longest Unix socket path accepted on every supported
// platform. macOS and the BSDs cap sun_path at 104 bytes including the NUL;
// Linux allows 108. Paths at or above this fall back to a short directory.
const MaxSocketPath = 100

// Resolve returns the directories for the current user without creating them.
func Resolve() (Dirs, error) {
	if base := os.Getenv("ROVER_DIR"); base != "" {
		return Dirs{
			Config: filepath.Join(base, "config"),
			State:  filepath.Join(base, "state"),
			Run:    filepath.Join(base, "run"),
		}, nil
	}
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Dirs{}, fmt.Errorf("home directory: %w", err)
		}
		base := filepath.Join(home, "Library", "Application Support", "Rover")
		return Dirs{Config: base, State: filepath.Join(base, "state"), Run: filepath.Join(base, "run")}, nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Dirs{}, fmt.Errorf("config directory: %w", err)
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Dirs{}, fmt.Errorf("home directory: %w", err)
		}
		state = filepath.Join(home, ".local", "state")
	}
	run := os.Getenv("XDG_RUNTIME_DIR")
	if run == "" {
		// No session manager (a container, a CI runner): fall back to the
		// state directory, which is still private to the user.
		run = filepath.Join(state, "rover")
	}
	return Dirs{
		Config: filepath.Join(cfg, "rover"),
		State:  filepath.Join(state, "rover"),
		Run:    filepath.Join(run, "rover"),
	}, nil
}

// Ensure creates the directories 0700 and refuses to continue if any of them
// is accessible to group or others.
func Ensure(d Dirs) error {
	for _, dir := range []string{d.Config, d.State, d.Run} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := CheckPrivate(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// ErrTooOpen is returned when a Rover file or directory can be reached by
// other users.
var ErrTooOpen = errors.New("permissions too open")

// CheckPrivate fails if path is readable, writable or searchable by anyone
// but its owner. want is the expected owner mode (0700 for a directory, 0600
// for a file); it is reported in the error so the fix is obvious.
func CheckPrivate(path string, want os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&0o077 != 0 {
		return fmt.Errorf("%w: %s is %04o, want %04o (chmod %o %q)", ErrTooOpen, path, fi.Mode().Perm(), want, want, path)
	}
	return nil
}

// SocketPath returns the daemon socket path. If the preferred path is too
// long for sun_path, it falls back to a short 0700 directory under the
// system temporary directory, which on macOS is already per-user.
func SocketPath(d Dirs) (string, error) {
	preferred := filepath.Join(d.Run, "roverd.sock")
	if len(preferred) < MaxSocketPath {
		return preferred, nil
	}
	// Different ROVER_DIRs (tests, a second profile) must not share a
	// fallback socket, so the run directory's hash is part of the name.
	sum := sha256.Sum256([]byte(d.Run))
	short := filepath.Join(os.TempDir(), fmt.Sprintf("rover-%d-%x", os.Getuid(), sum[:4]))
	if err := os.MkdirAll(short, 0o700); err != nil {
		return "", fmt.Errorf("socket fallback dir: %w", err)
	}
	if err := CheckPrivate(short, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(short, "roverd.sock")
	if len(p) >= MaxSocketPath {
		return "", fmt.Errorf("socket path %q is too long even after fallback; set TMPDIR or ROVER_DIR to a shorter path", p)
	}
	return p, nil
}
