// Package paths decides where Rover keeps its config, its state (the bbolt
// database and the audit log) and its runtime files (the roverd socket, pid
// and lock files), and checks that those directories are private.
//
// LESSON (M1):
//   - Never hard-code a home directory. The OS tells us where per-user config
//     lives (os.UserConfigDir, the XDG variables on Linux), and respecting
//     that is what lets tests and unusual setups work.
//   - A directory that other users can write to is a directory they can plant
//     files in: a fake socket, a symlink to somewhere else, a doctored audit
//     log. So every directory is 0700 (owner only), every file 0600, and we
//     refuse to run if a directory is looser, owned by someone else, or is a
//     symlink. Refusing is "fail closed": a loose directory costs the user a
//     clear error message, never a silent weakness.
//   - Unix socket paths are short: the kernel's sockaddr_un has room for about
//     104 bytes on macOS (108 on Linux), including the final NUL. A long home
//     directory can push the socket path past that, so we fall back to a
//     short private directory under the temp dir.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// MaxSocketPath is the longest socket path we use, in bytes. macOS allows 103
// usable bytes (104 including the NUL); we keep a small margin.
const MaxSocketPath = 100

// Dirs are Rover's per-user directories. All of them must be private (see
// Ensure and CheckPerms).
type Dirs struct {
	Config string // policy files and other configuration
	State  string // rover.db (bbolt) and audit.jsonl
	Run    string // roverd.pid, roverd.lock
	Socket string // the roverd Unix socket; normally Run/roverd.sock
}

// Resolve works out the directories for the current user. It does not create
// anything; call Ensure for that.
//
// If ROVER_DIR is set (tests and advanced use), everything lives under it:
// Config=$ROVER_DIR, State=$ROVER_DIR/state, Run=$ROVER_DIR/run. Anything
// running as the same user can set this variable and point a wrapper at a
// different daemon, but the same user can already do anything Rover could
// stop (that is outside the threat model, see plan §3).
func Resolve() (Dirs, error) {
	d, err := resolveDirs(runtime.GOOS)
	if err != nil {
		return Dirs{}, err
	}
	d.Socket, err = socketPath(d.Run)
	if err != nil {
		return Dirs{}, err
	}
	return d, nil
}

func resolveDirs(goos string) (Dirs, error) {
	if root := os.Getenv("ROVER_DIR"); root != "" {
		if !filepath.IsAbs(root) {
			return Dirs{}, fmt.Errorf("ROVER_DIR must be an absolute path, got %q", root)
		}
		root = filepath.Clean(root)
		return Dirs{Config: root, State: filepath.Join(root, "state"), Run: filepath.Join(root, "run")}, nil
	}

	switch goos {
	case "windows", "plan9", "js", "wasip1":
		return Dirs{}, fmt.Errorf("rover does not support %s", goos)
	case "darwin":
		// ~/Library/Application Support/Rover/{,state,run}
		cfg, err := os.UserConfigDir()
		if err != nil {
			return Dirs{}, err
		}
		root := filepath.Join(cfg, "Rover")
		return Dirs{Config: root, State: filepath.Join(root, "state"), Run: filepath.Join(root, "run")}, nil
	default: // Linux and other Unixes: the XDG base directory layout
		cfg, err := os.UserConfigDir() // $XDG_CONFIG_HOME or ~/.config; errors on a relative value
		if err != nil {
			return Dirs{}, err
		}
		state, err := xdgDir("XDG_STATE_HOME", homeLocalState)
		if err != nil {
			return Dirs{}, err
		}
		run, err := xdgDir("XDG_RUNTIME_DIR", func() (string, error) { return "", nil })
		if err != nil {
			return Dirs{}, err
		}
		runDir := filepath.Join(run, "rover")
		if run == "" {
			// No runtime dir (e.g. no systemd login session): use a per-user
			// directory in the temp dir. Another user could create it first;
			// CheckPerms then refuses it (owned by someone else), which is a
			// denial of service, not a bypass.
			runDir = tempRunDir()
		}
		return Dirs{
			Config: filepath.Join(cfg, "rover"),
			State:  filepath.Join(state, "rover"),
			Run:    runDir,
		}, nil
	}
}

// homeLocalState is the XDG default for $XDG_STATE_HOME: ~/.local/state.
func homeLocalState() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state"), nil
}

// xdgDir returns the XDG variable's value, or fallback() if it is unset. Like
// os.UserConfigDir, a relative value is an error (the XDG spec says relative
// paths are invalid).
func xdgDir(name string, fallback func() (string, error)) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback()
	}
	if !filepath.IsAbs(v) {
		return "", fmt.Errorf("$%s must be an absolute path, got %q", name, v)
	}
	return filepath.Clean(v), nil
}

// tempRunDir is $TMPDIR/rover-<uid> (or /tmp/rover-<uid>).
func tempRunDir() string {
	return filepath.Join(os.TempDir(), "rover-"+strconv.Itoa(os.Getuid()))
}

func socketPath(run string) (string, error) {
	sock := filepath.Join(run, "roverd.sock")
	if len(sock) <= MaxSocketPath {
		return sock, nil
	}
	sock = filepath.Join(tempRunDir(), "roverd.sock")
	if len(sock) > MaxSocketPath {
		return "", fmt.Errorf("socket path %q is longer than %d bytes even after falling back to the temp dir; set TMPDIR or ROVER_DIR to a shorter path", sock, MaxSocketPath)
	}
	return sock, nil
}

// all lists every directory Rover needs, without duplicates. The socket's
// directory is included because the long-path fallback puts it outside Run.
func (d Dirs) all() []string {
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range []string{d.Config, d.State, d.Run, filepath.Dir(d.Socket)} {
		if p == "" || p == "." || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Ensure creates the directories (0700) if they are missing and then runs
// CheckPerms. Existing directories are not chmod'ed: if one is loose,
// something or someone changed it, and the user should know.
func (d Dirs) Ensure() error {
	if d.Config == "" || d.State == "" || d.Run == "" || d.Socket == "" {
		return errors.New("paths: Dirs is incomplete; use Resolve")
	}
	for _, p := range d.all() {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
	}
	return d.CheckPerms()
}

// CheckPerms refuses (returns an error) if any directory is a symlink, is not
// a directory, is not owned by the current user, or has any group or other
// permission bits.
func (d Dirs) CheckPerms() error {
	uid := os.Getuid()
	for _, p := range d.all() {
		if err := checkDir(p, uid); err != nil {
			return err
		}
	}
	return nil
}

func checkDir(p string, uid int) error {
	// Lstat, not Stat: a symlink must be refused, not followed.
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it (it must be a real directory)", p)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", p)
	}
	owner, err := ownerUID(fi)
	if err != nil {
		return err
	}
	if owner != uid {
		return fmt.Errorf("%s is owned by uid %d, not by you (uid %d); refusing to use it", p, owner, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; it must be 0700 (fix with: chmod 700 %q)", p, perm, p)
	}
	return nil
}
