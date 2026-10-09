package ipc

import (
	"errors"
	"fmt"
	"net"
)

// ErrWrongUser is returned when the process on the other end of the socket
// does not run as the same user as roverd.
var ErrWrongUser = errors.New("peer is a different user")

// ErrWrongPID is returned when a wrapper's hello does not match what the
// kernel says about the connecting process.
var ErrWrongPID = errors.New("peer identity does not match hello")

// Creds is what the kernel reports about the process that connected.
type Creds struct {
	UID uint32
	PID int
}

// PeerCreds asks the kernel who is on the other end of a Unix socket. The
// answer cannot be forged by the peer: the kernel records the uid and pid
// of the process that called connect(2). (A same-user process can still
// connect, which is the documented limit in plan §3.)
func PeerCreds(conn *net.UnixConn) (Creds, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Creds{}, err
	}
	var c Creds
	var cerr error
	if err := raw.Control(func(fd uintptr) { c, cerr = peerCreds(int(fd)) }); err != nil {
		return Creds{}, err
	}
	if cerr != nil {
		return Creds{}, fmt.Errorf("peer credentials: %w", cerr)
	}
	return c, nil
}

// PeerUID is PeerCreds for callers that only need the user.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	c, err := PeerCreds(conn)
	return c.UID, err
}

// ParentPID returns the parent of pid as the kernel sees it. roverd uses it
// to check a wrapper's claim about which agent spawned it, so a process
// cannot join another agent's session just by naming its pid.
func ParentPID(pid int) (int, error) {
	return parentPID(pid)
}

// CheckPeer compares the connecting user with the daemon's own.
func CheckPeer(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("%w: uid %d, roverd runs as %d", ErrWrongUser, peer, self)
	}
	return nil
}

// CheckHello verifies a hello against the kernel's view of the peer: the
// connecting pid must be the wrapper_pid it claims, and that process's parent
// must be the client_pid it claims. parent is injectable for tests.
func CheckHello(peer Creds, wrapperPID, clientPID int, parent func(int) (int, error)) error {
	if peer.PID != wrapperPID {
		return fmt.Errorf("%w: connecting pid %d, hello says wrapper_pid %d", ErrWrongPID, peer.PID, wrapperPID)
	}
	ppid, err := parent(peer.PID)
	if err != nil {
		return fmt.Errorf("%w: cannot read parent of pid %d: %v", ErrWrongPID, peer.PID, err)
	}
	if ppid != clientPID {
		return fmt.Errorf("%w: pid %d has parent %d, hello says client_pid %d", ErrWrongPID, peer.PID, ppid, clientPID)
	}
	return nil
}
