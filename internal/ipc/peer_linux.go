//go:build linux

package ipc

import "golang.org/x/sys/unix"

// peerUID uses SO_PEERCRED, which returns the pid, uid and gid of the process
// that called connect(2).
func peerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
