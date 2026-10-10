// Package proxy is the thin wrapper that sits in the middle of an MCP stdio
// connection and does exactly what roverd tells it.
//
//	agent (Claude Code) --stdin-->   rover wrap   --stdin--> MCP server
//	agent               <--stdout--  rover wrap   <--stdout- MCP server
//	                                     │ decide / verdict
//	                                   roverd
//
// LESSON (A1, M1): this is a man-in-the-middle, used defensively. The wrapper
// reads one message, asks roverd for a verdict, applies it and moves on. It
// holds no policy and no state of its own, so there is nothing in it for an
// agent to tamper with and nothing that differs from one wrapper to the next.
//
// MCP stdio framing: each message is one line of JSON terminated by "\n",
// and messages must not contain raw newlines.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/DreadpiratePickles/rover/internal/framing"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Direction says which way a message is travelling.
type Direction string

// The two directions of an MCP stdio connection.
const (
	ClientToServer Direction = "c2s"
	ServerToClient Direction = "s2c"
)

// DefaultMaxMessage caps one message. Without a cap, a hostile server can send
// a single endless line and exhaust the gateway's memory (a DoS).
const DefaultMaxMessage = 16 << 20 // 16 MiB

// ErrMessageTooLarge is returned when a single message exceeds Wrapper.MaxMessage.
var ErrMessageTooLarge = framing.ErrTooLarge

// Decider is roverd as the wrapper sees it. *ipc.Client implements it; tests
// use a fake.
type Decider interface {
	Decide(dir string, raw []byte) (verdict ipc.Frame, release <-chan ipc.Frame, err error)
}

// Wrapper pumps both directions of one connection through a Decider.
type Wrapper struct {
	Decider    Decider
	MaxMessage int
	// Errf receives one-line diagnostics (stderr in the binary).
	Errf func(format string, a ...any)

	held sync.WaitGroup
}

// New returns a Wrapper with the default message limit.
func New(d Decider) *Wrapper {
	return &Wrapper{Decider: d, MaxMessage: DefaultMaxMessage, Errf: func(string, ...any) {}}
}

// LockedWriter serialises writes from both pumps to one destination. A
// blocked request is answered on the side it came from, so each side's
// writer can be reached from either goroutine.
type LockedWriter struct {
	mu sync.Mutex
	W  io.Writer
}

func (l *LockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.W.Write(p)
}

// Pump copies messages from src to dst, one line at a time, after roverd has
// seen each one. back is the writer facing src's side, used to answer a
// blocked request with a JSON-RPC error so the caller is not left waiting.
// Pump returns nil when src reaches EOF. Any failure to get a verdict ends
// the pump with an error: no verdict, no forwarding (fail closed).
func (w *Wrapper) Pump(src io.Reader, dst, back io.Writer, dir Direction) error {
	r := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := framing.ReadLine(r, w.MaxMessage)
		if len(bytes.TrimSpace(line)) > 0 {
			v, release, derr := w.Decider.Decide(string(dir), line)
			if derr != nil {
				return fmt.Errorf("no verdict from roverd, stopping session (fail closed): %w", derr)
			}
			if dir == ClientToServer && isRoverReply(line) {
				// roverd has it now; the server must never see it (inject.go).
				// A hold for it is dropped too: roverd never holds one.
				if v.Action != ipc.ActionBlock {
					w.Errf("roverd answered %s for a reply to a rover request; dropping it anyway", v.Action)
				}
			} else if v.Action == ipc.ActionHold {
				w.held.Add(1)
				go func(line []byte) {
					defer w.held.Done()
					final := <-release
					if aerr := w.apply(final, line, dst, back); aerr != nil {
						w.Errf("applying release for seq %d: %v", final.Seq, aerr)
					}
				}(line)
			} else if aerr := w.apply(v, line, dst, back); aerr != nil {
				return aerr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Wait blocks until every held message has been released and applied.
func (w *Wrapper) Wait() { w.held.Wait() }

func (w *Wrapper) apply(v ipc.Frame, line []byte, dst, back io.Writer) error {
	switch v.Action {
	case ipc.ActionForward:
		_, err := dst.Write(line) // the original bytes, never a re-encoding
		return err
	case ipc.ActionReplace:
		rep := v.ReplacementRaw
		if len(rep) == 0 || rep[len(rep)-1] != '\n' {
			rep = append(append([]byte{}, rep...), '\n')
		}
		_, err := dst.Write(rep)
		return err
	case ipc.ActionBlock:
		m := jsonrpc.Parse(line)
		w.Errf("blocked %s %s: %s", m.Kind, m.Method, v.Reason)
		if v.Drop {
			return nil // the requester cancelled it: no reply at all
		}
		if m.Kind != jsonrpc.KindRequest && !m.InvalidRequest() {
			return nil // notifications, responses and other invalid lines are simply dropped
		}
		var resp []byte
		if len(v.ResponseRaw) > 0 {
			// roverd built the reply (plan §5.1), e.g. an isError tool result.
			resp = v.ResponseRaw
			if resp[len(resp)-1] != '\n' {
				resp = append(append([]byte{}, resp...), '\n')
			}
		} else {
			var err error
			if resp, err = blockedResponse(m.ID, v); err != nil {
				return err
			}
		}
		_, err := back.Write(resp)
		return err
	default:
		return fmt.Errorf("unknown verdict action %q (refusing to guess)", v.Action)
	}
}

// BlockedErrorCode is the JSON-RPC error code Rover uses when it refuses a
// request. -32000 to -32099 are reserved for implementation-defined errors.
const BlockedErrorCode = -32000

func blockedResponse(id json.RawMessage, v ipc.Frame) ([]byte, error) {
	type errData struct {
		Rover   string   `json:"rover"`
		RuleIDs []string `json:"rule_ids,omitempty"`
	}
	type rpcErr struct {
		Code    int     `json:"code"`
		Message string  `json:"message"`
		Data    errData `json:"data"`
	}
	msg := "blocked by rover"
	if v.Reason != "" {
		msg += ": " + v.Reason
	}
	out := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcErr          `json:"error"`
	}{"2.0", id, rpcErr{BlockedErrorCode, msg, errData{"blocked", v.RuleIDs}}}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
