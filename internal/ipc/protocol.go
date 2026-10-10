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
	"strings"
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
	// TypeAdmin is a one-shot request from the rover CLI (instead of a
	// hello): roverd runs Op and answers admin_result (or error), then
	// closes. The peer uid check applies as for every connection.
	TypeAdmin       = "admin"
	TypeAdminResult = "admin_result"
)

// Admin operations (M4). TODO(M9): pin_approve and pin_reset will need OS
// authentication; until then the CLI is the only client.
const (
	OpPinList    = "pin_list"
	OpPinApprove = "pin_approve"
	OpPinReset   = "pin_reset"
	// OpObservationsDump returns the learn-mode observations (M6) as a JSON
	// array, oldest first, capped at 50,000 entries. Read-only.
	OpObservationsDump = "observations_dump"
	// OpDoctorState returns what `rover doctor` needs from roverd (M7): the
	// policy mode, whether a policy is loaded, and the tamper alerts.
	// Read-only.
	OpDoctorState = "doctor_state"
	// OpTamperResolve (after `rover install`) re-reads the config at Path,
	// takes its wrapped servers as the new baseline, clears its tamper
	// alerts and watches it; OpTamperForget (after `rover uninstall`) clears
	// its alerts and stops watching it. Both are audited.
	// TODO(M9): like pin approval, these should need OS authentication.
	OpTamperResolve = "tamper_resolve"
	OpTamperForget  = "tamper_forget"
)

// MaxPath bounds the path in a tamper_resolve or tamper_forget frame.
const MaxPath = 4096

// MaxToolName bounds the tool named in an admin frame.
const MaxToolName = 1024

// MinDigestPrefix is the shortest digest prefix pin_approve accepts.
const MinDigestPrefix = 12

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
	// ResponseRaw, on a block, is the complete JSON-RPC reply the wrapper
	// sends back to the requester instead of its default error (for example
	// a tools/call result with isError true that explains the rule).
	ResponseRaw []byte `json:"response_raw,omitempty"`

	// error, and an admin_result's note
	Message string `json:"message,omitempty"`

	// admin (ServerName names the server), admin_result
	Op   string `json:"op,omitempty"`
	Tool string `json:"tool,omitempty"`
	// Digest is the digest prefix a pin_approve approves: the one the
	// human saw in `rover pin list` (at least MinDigestPrefix hex digits).
	Digest string          `json:"digest,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	// Path is the config file of tamper_resolve and tamper_forget; Adapter
	// and Scope name its client and scope (tamper_resolve).
	Path    string `json:"path,omitempty"`
	Adapter string `json:"adapter,omitempty"`
	Scope   string `json:"scope,omitempty"`
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
		if err := ValidServerName(f.ServerName); err != nil {
			return fmt.Errorf("%w: hello: %w", ErrBadFrame, err)
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
		if len(f.ResponseRaw) > 0 && f.Action != ActionBlock {
			return fmt.Errorf("%w: response_raw is only valid on block", ErrBadFrame)
		}
	case TypeAdmin:
		return validateAdmin(f)
	case TypeBye, TypeError, TypeAdminResult:
	default:
		return fmt.Errorf("%w: unknown type %q", ErrBadFrame, f.Type)
	}
	return nil
}

func validateAdmin(f Frame) error {
	if (f.Path != "" || f.Adapter != "" || f.Scope != "") && f.Op != OpTamperResolve && f.Op != OpTamperForget {
		return fmt.Errorf("%w: %s takes no path, adapter or scope", ErrBadFrame, f.Op)
	}
	needServer, needTool := true, false
	switch f.Op {
	case OpPinList:
		needServer = f.ServerName != "" // optional: all servers
	case OpPinApprove:
		needTool = true
	case OpPinReset:
	case OpTamperResolve, OpTamperForget:
		if len(f.Path) == 0 || len(f.Path) > MaxPath || f.Path[0] != '/' || strings.ContainsRune(f.Path, 0) || f.ServerName != "" || f.Tool != "" {
			return fmt.Errorf("%w: %s needs an absolute path of at most %d bytes and nothing else", ErrBadFrame, f.Op, MaxPath)
		}
		if len(f.Adapter) > 64 || len(f.Scope) > MaxPath || (f.Op == OpTamperResolve) != (f.Adapter != "") {
			return fmt.Errorf("%w: tamper_resolve needs an adapter (1..64 bytes), tamper_forget none", ErrBadFrame)
		}
		return nil
	case OpObservationsDump, OpDoctorState:
		needServer = false
		if f.ServerName != "" {
			return fmt.Errorf("%w: %s takes no server", ErrBadFrame, f.Op)
		}
	default:
		return fmt.Errorf("%w: unknown admin op %q", ErrBadFrame, f.Op)
	}
	if needServer {
		if err := ValidServerName(f.ServerName); err != nil {
			return fmt.Errorf("%w: admin: %w", ErrBadFrame, err)
		}
	}
	if needTool && (f.Tool == "" || len(f.Tool) > MaxToolName) {
		return fmt.Errorf("%w: %s needs a tool name of 1..%d bytes", ErrBadFrame, f.Op, MaxToolName)
	}
	if !needTool && f.Tool != "" {
		return fmt.Errorf("%w: %s takes no tool", ErrBadFrame, f.Op)
	}
	if needTool != validDigestPrefix(f.Digest) {
		return fmt.Errorf("%w: %s needs a digest prefix of %d..64 lowercase hex digits only with a tool", ErrBadFrame, f.Op, MinDigestPrefix)
	}
	return nil
}

func validDigestPrefix(s string) bool {
	if len(s) < MinDigestPrefix || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Encode returns f as one line.
func Encode(f Frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// MaxServerName is the longest server name a hello may carry.
const MaxServerName = 128

// ValidServerName accepts 1..MaxServerName bytes of [A-Za-z0-9_.-]. Tool
// ids are "<server>/<tool>", split at the first "/", so a "/" in a server
// name would let "evil/echo" + "x" pass for server "evil", tool "echo/x"
// (review L4). Quotes, spaces and Unicode are refused too: the name ends
// up in Cedar entity ids and the audit log.
func ValidServerName(name string) error {
	if name == "" || len(name) > MaxServerName {
		return fmt.Errorf("server name must be 1..%d bytes", MaxServerName)
	}
	for i := 0; i < len(name); i++ {
		if !serverNameByte(name[i]) {
			return fmt.Errorf("server name %q may only contain A-Za-z0-9_.-", name)
		}
	}
	return nil
}

// SanitizeServerName turns any string (the default name, a command's base
// name) into a valid server name: every other byte becomes "_", and the
// result is cut to MaxServerName bytes ("_" if empty).
func SanitizeServerName(s string) string {
	if s == "" {
		return "_"
	}
	if len(s) > MaxServerName {
		s = s[:MaxServerName]
	}
	b := []byte(s)
	for i, c := range b {
		if !serverNameByte(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

func serverNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}
