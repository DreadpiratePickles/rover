//go:build !unix

package daemon

import "errors"

// ErrAlreadyRunning means another roverd holds the pid file lock.
var ErrAlreadyRunning = errors.New("roverd already running")

// PIDFile is unsupported off Unix.
type PIDFile struct{}

// AcquirePIDFile always fails off Unix (fail closed: no lock, no daemon).
func AcquirePIDFile(string) (*PIDFile, error) {
	return nil, errors.New("roverd: pid file locking is not supported on this OS")
}

// Release does nothing.
func (*PIDFile) Release() error { return nil }
