package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/DreadpiratePickles/rover/internal/framing"
)

// adminTimeout bounds one admin round trip.
const adminTimeout = 10 * time.Second

// AuthAdminTimeout bounds an admin request that shows the OS dialog first
// (pin_approve, pin_reset, policy_apply): the human needs time to answer it.
const AuthAdminTimeout = 3 * time.Minute

// Admin sends one admin frame to roverd at path and returns its
// admin_result. A connection failure is returned as is (wrapped), so the
// caller can tell "no daemon" (errors.Is ErrNoDaemon) from a refusal.
func Admin(path string, req Frame) (Frame, error) {
	req.Type = TypeAdmin
	if err := req.Validate(); err != nil {
		return Frame{}, err
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrNoDaemon, err)
	}
	defer func() { _ = conn.Close() }()
	limit := adminTimeout
	if req.Op == OpPinApprove || req.Op == OpPinReset || req.Op == OpPolicyApply {
		limit = AuthAdminTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(limit))
	line, err := Encode(req)
	if err != nil {
		return Frame{}, err
	}
	if _, err = conn.Write(line); err != nil {
		return Frame{}, err
	}
	resp, err := framing.ReadLine(bufio.NewReader(conn), MaxFrame)
	if err != nil && (!errors.Is(err, io.EOF) || len(resp) == 0) {
		return Frame{}, fmt.Errorf("waiting for admin_result: %w", err)
	}
	f, err := Parse(resp)
	if err != nil {
		return Frame{}, err
	}
	switch f.Type {
	case TypeAdminResult:
		return f, nil
	case TypeError:
		return Frame{}, fmt.Errorf("roverd: %s", f.Message)
	default:
		return Frame{}, fmt.Errorf("%w: expected admin_result, got %s", ErrBadFrame, f.Type)
	}
}

// ErrNoDaemon wraps a failure to connect to roverd's socket.
var ErrNoDaemon = errors.New("roverd is not running")
