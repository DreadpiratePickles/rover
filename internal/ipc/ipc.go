// Package ipc is the protocol between a wrapper (`rover wrap`, one per MCP
// server) and roverd (`rover daemon`, one per user).
//
// LESSON (M1): the wrapper is thin. For every MCP message it asks roverd
// "what should I do with this?" and does what it is told. They talk over a
// Unix socket: a file-system path that two processes on the same machine can
// connect through, like a private phone line. Two things keep it private:
//
//  1. File permissions. The socket file is 0600 inside a 0700 directory, so
//     the kernel refuses connect() from any other user before we see it.
//  2. Peer credentials. On every accepted connection roverd asks the KERNEL
//     which user is on the other end (SO_PEERCRED on Linux, LOCAL_PEERCRED
//     on macOS) and hangs up unless it is the same user as roverd. The
//     kernel fills this in; the peer cannot lie about it. This is the second
//     lock on the same door: if a directory permission is ever wrong, the
//     peer check still holds.
//
// Wire format: one JSON object per line ("\n"-terminated), at most MaxLine
// bytes. Every line is an envelope with a "type" and one member named after
// that type:
//
//	{"type":"hello","hello":{"version":1,"wrapper_pid":4242,"client_pid":4200,"server_name":"echo","server_cmd_sha256":"9f86…","transport":"stdio"}}
//	{"type":"welcome","welcome":{"session_id":"a1b2c3d4e5f60718293a4b5c"}}
//	{"type":"decide","decide":{"session_id":"a1b2c3d4e5f60718293a4b5c","seq":1,"dir":"c2s","raw":{"jsonrpc":"2.0","id":1,"method":"ping"}}}
//	{"type":"verdict","verdict":{"seq":1,"action":"forward","rule_ids":[]}}
//	{"type":"release","release":{"seq":7,"action":"block","replacement_raw":{"jsonrpc":"2.0","id":3,"error":{"code":-32001,"message":"denied"}}}}
//	{"type":"bye","bye":{"session_id":"a1b2c3d4e5f60718293a4b5c"}}
//
// Anything else - an unknown type, an unknown field, a missing or extra
// member, trailing data, an over-long line - is a protocol error, and the
// receiver closes the connection. Parsing is strict on purpose: a lenient
// parser is a place for two programs to disagree about what a message means.
package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// Version is the protocol version sent in Hello. roverd refuses others.
const Version = 1

// MaxLine caps one line on the socket. A decide carries a whole MCP message
// (up to proxy.DefaultMaxMessage, 16 MiB) plus a small envelope, so the cap
// is 16 MiB plus 64 KiB of headroom for that envelope.
const MaxLine = proxy.DefaultMaxMessage + 64<<10

// The message types. Each is the value of the envelope's "type" field and
// also the name of the member that carries the payload.
const (
	TypeHello   = "hello"
	TypeWelcome = "welcome"
	TypeDecide  = "decide"
	TypeVerdict = "verdict"
	TypeRelease = "release"
	TypeBye     = "bye"
)

// Directions, as sent in Decide.Dir.
const (
	DirC2S = string(proxy.ClientToServer)
	DirS2C = string(proxy.ServerToClient)
)

// Verdict actions, as sent in Verdict.Action and Release.Action.
const (
	ActionForward = proxy.ActionForward
	ActionBlock   = proxy.ActionBlock
	ActionReplace = proxy.ActionReplace
	ActionHold    = proxy.ActionHold
)

// Errors. Every decode failure wraps ErrProtocol.
var (
	ErrProtocol     = errors.New("ipc protocol error")
	ErrUnknownType  = fmt.Errorf("%w: unknown message type", ErrProtocol)
	ErrLineTooLarge = fmt.Errorf("%w: line exceeds %d bytes", ErrProtocol, MaxLine)
)

// Hello is the wrapper's first message on a new connection.
type Hello struct {
	Version         int    `json:"version"`
	WrapperPID      int    `json:"wrapper_pid"`
	ClientPID       int    `json:"client_pid"`        // the wrapper's parent: the agent app. Sessions are keyed on it.
	ServerName      string `json:"server_name"`       // --name, or the base name of the server command
	ServerCmdSHA256 string `json:"server_cmd_sha256"` // hex SHA-256 of the server argv joined with "\x00"
	Transport       string `json:"transport"`         // "stdio" in M1
}

// Welcome is roverd's answer to Hello.
type Welcome struct {
	SessionID string `json:"session_id"`
}

// Decide asks roverd about one MCP message. Seq strictly increases on each
// connection (across both directions), so a Verdict's Seq names exactly one
// Decide.
type Decide struct {
	SessionID string          `json:"session_id"`
	Seq       uint64          `json:"seq"`
	Dir       string          `json:"dir"` // DirC2S or DirS2C
	Raw       json.RawMessage `json:"raw"` // the MCP message, byte-for-byte as the wrapper read it (trimmed)
}

// Verdict is roverd's answer to one Decide.
type Verdict struct {
	Seq            uint64          `json:"seq"`
	Action         string          `json:"action"`
	ReplacementRaw json.RawMessage `json:"replacement_raw,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	RuleIDs        []string        `json:"rule_ids"` // always an array on the wire, never null
}

// Release is pushed by roverd when a held message is resolved (M9). The M1
// wrapper never has a held message, so it ignores releases.
type Release struct {
	Seq            uint64          `json:"seq"`
	Action         string          `json:"action"`
	ReplacementRaw json.RawMessage `json:"replacement_raw,omitempty"`
}

// Bye ends a connection politely. Closing the socket means the same thing.
type Bye struct {
	SessionID string `json:"session_id"`
}

// Message is the envelope: Type plus exactly one non-nil payload, the one
// named by Type.
type Message struct {
	Type    string   `json:"type"`
	Hello   *Hello   `json:"hello,omitempty"`
	Welcome *Welcome `json:"welcome,omitempty"`
	Decide  *Decide  `json:"decide,omitempty"`
	Verdict *Verdict `json:"verdict,omitempty"`
	Release *Release `json:"release,omitempty"`
	Bye     *Bye     `json:"bye,omitempty"`
}

// payloads reports the type name of every non-nil payload, in field order.
func (m *Message) payloads() []string {
	var out []string
	add := func(set bool, name string) {
		if set {
			out = append(out, name)
		}
	}
	add(m.Hello != nil, TypeHello)
	add(m.Welcome != nil, TypeWelcome)
	add(m.Decide != nil, TypeDecide)
	add(m.Verdict != nil, TypeVerdict)
	add(m.Release != nil, TypeRelease)
	add(m.Bye != nil, TypeBye)
	return out
}

func knownType(t string) error {
	switch t {
	case TypeHello, TypeWelcome, TypeDecide, TypeVerdict, TypeRelease, TypeBye:
		return nil
	}
	return fmt.Errorf("%w %q", ErrUnknownType, t)
}

func (m *Message) check() error {
	if err := knownType(m.Type); err != nil {
		return err
	}
	if p := m.payloads(); len(p) != 1 || p[0] != m.Type {
		return fmt.Errorf("%w: type %q with payload(s) %v", ErrProtocol, m.Type, p)
	}
	return nil
}

// Encode returns m as one wire line, including the trailing "\n".
//
// A Decide's Raw is spliced in byte-for-byte. Going through json.Marshal
// would "compact" it (strip whitespace, escape <, > and &), and roverd
// should inspect exactly the bytes the wrapper will forward. Raw must
// therefore be valid JSON with no newline in it.
func Encode(m Message) ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	var b []byte
	var err error
	switch {
	case m.Decide != nil:
		b, err = encodeDecide(m.Decide)
	case m.Verdict != nil && m.Verdict.RuleIDs == nil:
		v := *m.Verdict
		v.RuleIDs = []string{} // "rule_ids":[] - never null
		b, err = json.Marshal(Message{Type: m.Type, Verdict: &v})
	default:
		b, err = json.Marshal(m)
	}
	if err != nil {
		return nil, err
	}
	if len(b)+1 > MaxLine {
		return nil, ErrLineTooLarge
	}
	return append(b, '\n'), nil
}

func encodeDecide(d *Decide) ([]byte, error) {
	raw := bytes.TrimSpace(d.Raw)
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, fmt.Errorf("%w: decide raw is not valid JSON", ErrProtocol)
	}
	if bytes.IndexByte(raw, '\n') >= 0 {
		return nil, fmt.Errorf("%w: decide raw contains a newline", ErrProtocol)
	}
	head, err := json.Marshal(struct {
		SessionID string `json:"session_id"`
		Seq       uint64 `json:"seq"`
		Dir       string `json:"dir"`
	}{d.SessionID, d.Seq, d.Dir})
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(head)+len(raw)+64)
	b = append(b, `{"type":"decide","decide":`...)
	b = append(b, head[:len(head)-1]...) // drop the closing '}'
	b = append(b, `,"raw":`...)
	b = append(b, raw...)
	b = append(b, "}}"...)
	return b, nil
}

// Decode parses one wire line (with or without its trailing "\n").
// Attacker-controlled input is bounded twice: by MaxLine here, and by
// encoding/json's own nesting-depth limit (10000) inside.
func Decode(line []byte) (Message, error) {
	if len(line) > MaxLine {
		return Message{}, ErrLineTooLarge
	}
	// First look only at "type", so an unknown type is reported as such
	// (and not as "unknown field" for its payload member).
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if err := knownType(head.Type); err != nil {
		return Message{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var m Message
	if err := dec.Decode(&m); err != nil {
		return Message{}, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	// Exactly one JSON value per line: anything after it is an error.
	if _, err := dec.Token(); err != io.EOF {
		return Message{}, fmt.Errorf("%w: trailing data after message", ErrProtocol)
	}
	if err := m.check(); err != nil {
		return Message{}, err
	}
	return m, nil
}
