//go:build linux || darwin

package ipc

import (
	"errors"
	"net"
)

// withFD runs fn with conn's file descriptor, without taking it out of Go's
// network poller (which conn.File() would do).
func withFD(conn *net.UnixConn, fn func(fd int)) error {
	if conn == nil {
		return errors.New("ipc: nil connection")
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { fn(int(fd)) })
}
