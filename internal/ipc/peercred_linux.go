package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID asks the kernel which user is on the other end of conn.
//
// Linux: getsockopt(SOL_SOCKET, SO_PEERCRED) returns the pid, uid and gid
// the peer had when it called connect(). The kernel records them; the peer
// cannot forge them.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	var (
		cred *unix.Ucred
		cerr error
	)
	err := withFD(conn, func(fd int) {
		cred, cerr = unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}
