// Package ipc is the wire protocol between a `rover wrap` process and roverd
// (plan §4.3): newline-delimited JSON over a Unix socket.
//
// One connection per wrapper. The wrapper speaks first with a hello; roverd
// answers welcome with the session id. After that the wrapper sends a decide
// for every MCP message it reads and roverd answers with a verdict carrying
// the same seq. A verdict of "hold" is provisional: roverd later pushes a
// release with the final action for that seq, while other messages keep
// flowing. Either side may send bye; closing the socket means the same.
//
// The MCP message travels inside "raw" as base64 (Go's encoding for []byte).
// A JSON string would do for valid UTF-8, but the gateway must forward the
// original bytes even when they are not valid UTF-8 or not valid JSON, and
// base64 is the only encoding that never alters them.
package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the protocol version carried in hello. roverd refuses a hello
// from a different version so a stale wrapper and a new daemon fail loudly
// instead of mis-parsing each other.
const Version = 1

// MaxFrame bounds one line on the socket. An MCP message is capped at 16 MiB
// by the proxy; base64 inflates it by 4/3, plus a little JSON around it.
const MaxFrame = 16<<20*4/3 + 64<<10

// Message types.
const (
	TypeHello   = "hello"
	TypeWelcome = "welcome"
	TypeDecide  = "decide"
	TypeVerdict = "verdict"
	TypeRelease = "release"
	TypeBye     = "bye"
	TypeError   = "error" // roverd -> wrapper, fatal for the connection
)

// Actions a verdict or release can carry.
const (
	ActionForward = "forward"
	ActionBlock   = "block"
	ActionReplace = "replace"
	ActionHold    = "hold"
)

// Frame is the union of every message. Type says which fields are meaningful.
type Frame struct {
	Type string `json:"type"`

	// hello
	Version      int    `json:"version,omitempty"`
	WrapperPID   int    `json:"wrapper_pid,omitempty"`
	ClientPID    int    `json:"client_pid,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
	ServerCmdSHA string `json:"server_cmd_sha256,omitempty"`
	Transport    string `json:"transport,omitempty"` // "stdio" (M1) or "http" (M11)

	// welcome, decide, bye
	SessionID string `json:"session_id,omitempty"`

	// decide, verdict, release
	Seq uint64 `json:"seq,omitempty"`
	Dir string `json:"dir,omitempty"` // "c2s" or "s2c"
	Raw []byte `json:"raw,omitempty"` // base64 on the wire

	// verdict, release
	Action         string   `json:"action,omitempty"`
	ReplacementRaw []byte   `json:"replacement_raw,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	RuleIDs        []string `json:"rule_ids,omitempty"`

	// error
	Message string `json:"message,omitempty"`
}

// ErrBadFrame wraps every parse or validation failure.
var ErrBadFrame = errors.New("bad ipc frame")

// Parse decodes one line and checks the fields the type requires. It is the
// daemon's first contact with bytes from another process, so it is strict:
// anything it does not understand is an error, and the daemon drops the
// connection (fail closed) rather than guessing.
func Parse(line []byte) (Frame, error) {
	if len(line) > MaxFrame {
		return Frame{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrBadFrame, len(line), MaxFrame)
	}
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrBadFrame, err)
	}
	if err := f.Validate(); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// Validate checks the invariants for f.Type.
func (f Frame) Validate() error {
	switch f.Type {
	case TypeHello:
		if f.Version != Version {
			return fmt.Errorf("%w: protocol version %d, want %d", ErrBadFrame, f.Version, Version)
		}
		if f.WrapperPID <= 0 || f.ClientPID <= 0 {
			return fmt.Errorf("%w: hello needs wrapper_pid and client_pid", ErrBadFrame)
		}
		if f.ServerName == "" || len(f.ServerName) > 128 {
			return fmt.Errorf("%w: hello needs server_name (1..128 bytes)", ErrBadFrame)
		}
		if f.Transport != "stdio" && f.Transport != "http" {
			return fmt.Errorf("%w: unknown transport %q", ErrBadFrame, f.Transport)
		}
	case TypeWelcome:
		if f.SessionID == "" {
			return fmt.Errorf("%w: welcome needs session_id", ErrBadFrame)
		}
	case TypeDecide:
		if f.SessionID == "" || f.Seq == 0 || (f.Dir != "c2s" && f.Dir != "s2c") || len(f.Raw) == 0 {
			return fmt.Errorf("%w: decide needs session_id, seq, dir and raw", ErrBadFrame)
		}
	case TypeVerdict, TypeRelease:
		if f.Seq == 0 {
			return fmt.Errorf("%w: %s needs seq", ErrBadFrame, f.Type)
		}
		switch f.Action {
		case ActionForward, ActionBlock:
		case ActionReplace:
			if len(f.ReplacementRaw) == 0 {
				return fmt.Errorf("%w: replace needs replacement_raw", ErrBadFrame)
			}
		case ActionHold:
			if f.Type == TypeRelease {
				return fmt.Errorf("%w: a release cannot hold", ErrBadFrame)
			}
		default:
			return fmt.Errorf("%w: unknown action %q", ErrBadFrame, f.Action)
		}
	case TypeBye, TypeError:
	default:
		return fmt.Errorf("%w: unknown type %q", ErrBadFrame, f.Type)
	}
	return nil
}

// Encode returns f as one line.
func Encode(f Frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
