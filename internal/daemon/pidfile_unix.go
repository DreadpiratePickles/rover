//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// ErrAlreadyRunning means another roverd holds the pid file lock.
var ErrAlreadyRunning = errors.New("roverd already running")

// PIDFile is roverd's run/roverd.pid, locked for as long as roverd runs.
//
// LESSON (M1): flock(2) is an advisory lock the kernel attaches to an open
// file. LOCK_EX|LOCK_NB means "exclusive, and fail at once instead of
// waiting". The kernel releases it automatically when the process dies, even
// by SIGKILL, so a crashed roverd never leaves a lock that blocks the next
// one (unlike "does the pid file exist?", which a crash leaves behind).
type PIDFile struct {
	f *os.File
}

// AcquirePIDFile locks path and writes our pid into it. If another process
// holds the lock it returns ErrAlreadyRunning.
func AcquirePIDFile(path string) (*PIDFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: path is roverd's own run/roverd.pid inside a 0700 dir
	if err != nil {
		return nil, err
	}
	if err := flock(f, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := writePID(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return &PIDFile{f: f}, nil
}

func writePID(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return err
	}
	return f.Sync()
}

// Release empties the pid file and drops the lock. The file itself stays:
// removing it would race with a new roverd that has just opened it.
func (p *PIDFile) Release() error {
	if p == nil || p.f == nil {
		return nil
	}
	_ = p.f.Truncate(0)
	err := p.f.Close() // closing the last descriptor releases the flock
	p.f = nil
	return err
}

func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	cerr := rc.Control(func(fd uintptr) {
		for {
			ferr = unix.Flock(int(fd), how)
			if !errors.Is(ferr, unix.EINTR) {
				return
			}
		}
	})
	if cerr != nil {
		return cerr
	}
	return ferr
}
