package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The actions a Verdict can carry. They are the same strings roverd sends on
// the wire (see internal/ipc).
const (
	ActionForward = "forward" // send the original bytes on, unchanged
	ActionReplace = "replace" // send ReplacementRaw on instead of the original
	ActionBlock   = "block"   // drop it; optionally answer the sender with ReplacementRaw
	ActionHold    = "hold"    // wait for a human (M9); the M1 wrapper cannot, so it stops
)

// Verdict is the answer to "what should happen to this message?".
type Verdict struct {
	Action         string
	ReplacementRaw []byte // for replace: the new message; for block: an optional reply to the sender
	Reason         string
}

// Decider decides the fate of one message. In the real wrapper it is roverd,
// reached over a Unix socket (ipc.Client); tests use a fake.
//
// raw is the message with surrounding whitespace (including the newline)
// trimmed. Decide must not keep raw after it returns.
type Decider interface {
	Decide(dir Direction, raw []byte) (Verdict, error)
}

// ErrStopped wraps every reason Pump stops early on purpose: a Decide error,
// a hold the wrapper cannot honour, an unknown action or a bad replacement.
var ErrStopped = errors.New("session stopped (fail closed)")

// Pipe is the M1 wrapper's core: two pumps (one per direction) that ask a
// Decider about every message and then apply its verdict.
//
// LESSON (M1): notice what Pump does when anything is unexpected - an error
// from roverd, a verdict it doesn't understand, a "hold" it can't wait for.
// It returns an error and the caller stops the whole session. That is
// "fail closed": when the security control is unsure, nothing gets through.
// The opposite ("roverd is down, so just forward") would turn killing roverd
// into a bypass. With fail closed, killing roverd is only a denial of service.
type Pipe struct {
	ToServer   io.Writer // the MCP server's stdin
	ToClient   io.Writer // the agent's side (our stdout)
	Decider    Decider
	MaxMessage int // 0 means DefaultMaxMessage

	// Both pumps can write to the same writer at once (a c2s block reply goes
	// to the client while the s2c pump forwards to it), so each writer has
	// its own lock and every message is written in a single Write call.
	serverMu, clientMu sync.Mutex
}

// Pump reads messages from src, travelling in direction dir, until EOF (nil)
// or until something goes wrong (an error; the caller must stop the session).
// For each message it asks the Decider and then:
//
//   - forward: writes the ORIGINAL bytes, never a re-encoding, to the
//     destination (the server for c2s, the client for s2c).
//   - replace: writes ReplacementRaw plus "\n" to the destination.
//   - block: forwards nothing. A non-empty ReplacementRaw is a reply for the
//     SENDER (for example a JSON-RPC error answering a blocked request), so it
//     goes back the way the message came.
//   - hold, any unknown action, or a Decide error: returns an error.
func (p *Pipe) Pump(src io.Reader, dir Direction) error {
	if p.Decider == nil {
		return fmt.Errorf("%w: no decider", ErrStopped)
	}
	limit := p.MaxMessage
	if limit <= 0 {
		limit = DefaultMaxMessage
	}
	r := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := ReadLine(r, limit)
		if raw := bytes.TrimSpace(line); len(raw) > 0 {
			if aerr := p.apply(dir, line, raw); aerr != nil {
				return aerr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (p *Pipe) apply(dir Direction, line, raw []byte) error {
	v, err := p.Decider.Decide(dir, raw)
	if err != nil {
		return fmt.Errorf("%w: decide: %w", ErrStopped, err)
	}
	switch v.Action {
	case ActionForward:
		return p.write(dir, line)
	case ActionReplace:
		msg, err := framed(v.ReplacementRaw)
		if err != nil {
			return err
		}
		return p.write(dir, msg)
	case ActionBlock:
		if len(v.ReplacementRaw) == 0 {
			return nil
		}
		msg, err := framed(v.ReplacementRaw)
		if err != nil {
			return err
		}
		return p.write(dir.other(), msg)
	case ActionHold:
		return fmt.Errorf("%w: hold is not supported before M9", ErrStopped)
	default:
		return fmt.Errorf("%w: unknown verdict action %q", ErrStopped, v.Action)
	}
}

// framed turns a replacement into exactly one stdio message. A replacement
// with a newline inside would smuggle extra messages onto the stream, so it
// is refused rather than "cleaned up".
func framed(raw []byte) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty replacement", ErrStopped)
	}
	if bytes.IndexByte(raw, '\n') >= 0 {
		return nil, fmt.Errorf("%w: replacement contains a newline", ErrStopped)
	}
	out := make([]byte, 0, len(raw)+1)
	return append(append(out, raw...), '\n'), nil
}

// write sends one framed message towards the receiver of direction dir:
// c2s messages go to the server, s2c messages go to the client.
func (p *Pipe) write(dir Direction, msg []byte) error {
	w, mu := p.ToServer, &p.serverMu
	if dir == ServerToClient {
		w, mu = p.ToClient, &p.clientMu
	}
	if w == nil {
		return fmt.Errorf("%w: no writer for %s", ErrStopped, dir)
	}
	mu.Lock()
	defer mu.Unlock()
	_, err := w.Write(msg)
	return err
}
