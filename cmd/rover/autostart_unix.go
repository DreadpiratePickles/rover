//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// lockTimeout bounds the wait for another wrapper's auto-start. That wrapper
// holds the lock for at most about 4 s (spawn plus a 3 s connect wait), so
// this only expires if something is badly stuck; then we fail closed rather
// than hang the agent forever.
const lockTimeout = 10 * time.Second

// autostart starts roverd and connects to it.
//
// LESSON (M1): an agent app often starts all its MCP servers at once, so
// several wrappers can find roverd missing at the same moment. Without
// coordination each would start its own roverd. run/roverd.lock is the
// coordination: whoever gets the flock first starts roverd and waits for its
// socket; the others queue on the lock, and when they get it, find roverd
// already answering. (roverd's own pid-file lock would stop a second daemon
// anyway; this lock just avoids starting one for nothing.)
func autostart(d paths.Dirs) (*ipc.Client, error) {
	if err := d.Ensure(); err != nil { // creates the dirs on first use; refuses loose permissions
		return nil, err
	}
	lockPath := filepath.Join(d.Run, lockFileName)
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: fixed name inside rover's own 0700 run dir
	if err != nil {
		return nil, err
	}
	// Closing our only descriptor drops the flock. os.OpenFile sets
	// O_CLOEXEC, so the roverd we spawn does not inherit (and keep) it.
	defer func() { _ = lock.Close() }()
	if err := lockWait(lock, lockTimeout); err != nil {
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}

	// Someone else may have started roverd while we waited for the lock.
	if c, err := ipc.Dial(d.Socket, time.Second); err == nil {
		return c, nil
	}
	if err := spawnDaemon(d); err != nil {
		return nil, err
	}
	// Keep holding the lock until roverd answers (or we give up), so the
	// wrappers queued behind us connect instead of spawning another one.
	return dialRetry(d.Socket, 3*time.Second)
}

// lockWait takes an exclusive flock on f, polling so that it can give up.
func lockWait(f *os.File, timeout time.Duration) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		var ferr error
		if cerr := rc.Control(func(fd uintptr) {
			for {
				ferr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
				if !errors.Is(ferr, unix.EINTR) {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		if !errors.Is(ferr, unix.EWOULDBLOCK) {
			return ferr // nil: locked
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("still held by another rover after %v", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// detach puts cmd in a new session: no controlling terminal, and not in our
// process group, so signals aimed at the agent or the wrapper miss it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
