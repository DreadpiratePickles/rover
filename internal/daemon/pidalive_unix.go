//go:build unix

package daemon

import (
	"errors"
	"syscall"
)

// pidAlive is kill(pid, 0): the process exists (EPERM means it exists but
// belongs to someone else).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
