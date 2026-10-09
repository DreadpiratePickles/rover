package ipc

import (
	"errors"
	"fmt"
	"net"
)

// ErrWrongUser is returned when the process on the other end of the socket
// does not run as the same user as roverd.
var ErrWrongUser = errors.New("peer is a different user")

// PeerUID asks the kernel who is on the other end of a Unix socket. It
// cannot be spoofed by the peer: the kernel records the credentials of the
// process that connected. (A same-user process can still connect, which is
// the documented limit in plan §3.)
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	if err := raw.Control(func(fd uintptr) { uid, cerr = peerUID(int(fd)) }); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, fmt.Errorf("peer credentials: %w", cerr)
	}
	return uid, nil
}

// CheckPeer compares the connecting user with the daemon's own.
func CheckPeer(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("%w: uid %d, roverd runs as %d", ErrWrongUser, peer, self)
	}
	return nil
}
