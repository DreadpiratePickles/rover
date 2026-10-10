package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Listen creates the roverd socket at path and returns its listener.
//
// If a file is already there:
//   - a live daemon answering on it is an error (two roverds must not share
//     one socket);
//   - a dead socket left by a crash is removed;
//   - anything that is not a socket is an error: we never delete a file we
//     did not create.
//
// The socket is chmod'ed 0600. The directory it lives in must already be
// 0700 (internal/paths makes sure), which also covers the short moment
// between bind() and chmod(). Closing the listener removes the socket file.
func Listen(path string) (*net.UnixListener, error) {
	if err := removeStale(path); err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("ipc: chmod socket: %w", err)
	}
	return l, nil
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("ipc: %s exists and is not a socket; refusing to remove it", path)
	}
	if c, derr := net.DialTimeout("unix", path, 500*time.Millisecond); derr == nil {
		_ = c.Close()
		return fmt.Errorf("ipc: %s is in use by a running daemon", path)
	}
	return os.Remove(path)
}

// Guard accepts connections and lets through only those whose peer is the
// same user as us. Rejected connections are closed at once, before a single
// byte is read from them, and counted.
type Guard struct {
	// UID is the only user allowed to connect. NewGuard sets it to ours.
	UID uint32
	// PeerUID reads the peer's uid. Tests inject a fake; NewGuard sets PeerUID.
	PeerUID func(*net.UnixConn) (uint32, error)
	// OnReject, if set, is told about each rejected connection (for a log line).
	OnReject func(err error)

	rejected atomic.Uint64
}

// NewGuard returns a Guard for the current user using the real PeerUID.
func NewGuard() (*Guard, error) {
	uid, err := CurrentUID()
	if err != nil {
		return nil, err
	}
	return &Guard{UID: uid, PeerUID: PeerUID}, nil
}

// CurrentUID returns os.Getuid() as a uint32, or an error where there is no
// such thing (Windows reports -1).
func CurrentUID() (uint32, error) {
	uid := os.Getuid()
	if uid < 0 || int64(uid) > math.MaxUint32 {
		return 0, errors.New("ipc: no usable uid on this OS")
	}
	return uint32(uid), nil //nolint:gosec // G115: range-checked on the line above
}

// ErrPeerRejected is reported to OnReject when a peer is not our user.
var ErrPeerRejected = errors.New("ipc: peer is a different user")

// Check returns nil only if conn's peer is g.UID. Any failure to find out is
// a rejection too (fail closed).
func (g *Guard) Check(conn *net.UnixConn) error {
	if g.PeerUID == nil {
		return errors.New("ipc: no peer credential checker")
	}
	uid, err := g.PeerUID(conn)
	if err != nil {
		return fmt.Errorf("ipc: reading peer credentials: %w", err)
	}
	if uid != g.UID {
		return fmt.Errorf("%w (uid %d, want %d)", ErrPeerRejected, uid, g.UID)
	}
	return nil
}

// Accept waits for the next connection whose peer passes Check. Rejected
// connections never reach the caller. It returns an error only when the
// listener itself fails (for example because it was closed).
func (g *Guard) Accept(l *net.UnixListener) (*net.UnixConn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if cerr := g.Check(c); cerr != nil {
			_ = c.Close()
			g.rejected.Add(1)
			if g.OnReject != nil {
				g.OnReject(cerr)
			}
			continue
		}
		return c, nil
	}
}

// Rejected returns how many connections Accept has turned away.
func (g *Guard) Rejected() uint64 { return g.rejected.Load() }
