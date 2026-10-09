//go:build !linux && !darwin

package ipc

import "errors"

var errUnsupported = errors.New("peer credentials are not supported on this platform")

// Unsupported platforms fail closed: no credentials means no connection.
func peerCreds(int) (Creds, error) { return Creds{}, errUnsupported }

func parentPID(int) (int, error) { return 0, errUnsupported }
