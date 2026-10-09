//go:build !linux && !darwin

package ipc

import (
	"errors"
	"net"
)

// PeerUID is only implemented on Linux and macOS. Everywhere else it returns
// an error, so every connection is rejected (fail closed).
func PeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("ipc: peer credentials are not supported on this OS")
}
