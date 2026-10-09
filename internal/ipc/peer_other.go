//go:build !linux && !darwin

package ipc

import "errors"

// Unsupported platforms fail closed: no credentials means no connection.
func peerUID(int) (uint32, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
