// Package proxy sits in the middle of an MCP stdio connection.
//
//	agent (Claude Code) --stdin-->    rover     --stdin--> MCP server
//	agent               <--stdout--   rover     <--stdout- MCP server
//
// LESSON (A1): this is a man-in-the-middle, used defensively. Every security
// feature in Track A (policy, pinning, inspection, redaction) is a hook in
// the Pump loop below. A1 only observes; A2 starts saying "no".
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
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Direction says which way a message is travelling.
type Direction string

// The two directions of an MCP stdio connection.
const (
	ClientToServer Direction = "c2s"
	ServerToClient Direction = "s2c"
)

func (d Direction) other() Direction {
	if d == ClientToServer {
		return ServerToClient
	}
	return ClientToServer
}

// DefaultMaxMessage caps one message. Without a cap, a hostile server can send
// a single endless line and exhaust the gateway's memory (a DoS).
const DefaultMaxMessage = 16 << 20 // 16 MiB

// ErrMessageTooLarge is returned when a single message exceeds Session.MaxMessage.
var ErrMessageTooLarge = errors.New("message exceeds size limit")

type pending struct {
	method string
	tool   string
	start  time.Time
}

// Session holds state shared by both directions of one connection.
type Session struct {
	ID         string
	Log        *audit.Logger
	LogBodies  bool
	MaxMessage int
	now        func() time.Time

	mu      sync.Mutex
	pending map[string]pending // key: "<requester dir>:<raw id>"
}

// NewSession returns a Session that logs bodies and uses DefaultMaxMessage.
func NewSession(id string, log *audit.Logger) *Session {
	return &Session{ID: id, Log: log, LogBodies: true, MaxMessage: DefaultMaxMessage, now: time.Now, pending: map[string]pending{}}
}

// Pump copies messages from src to dst, one line at a time, logging each one
// before forwarding it. It forwards the original bytes, never a re-encoding.
// It returns nil when src reaches EOF.
func (s *Session) Pump(src io.Reader, dst io.Writer, dir Direction) error {
	r := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := readLine(r, s.MaxMessage)
		if len(bytes.TrimSpace(line)) > 0 {
			if lerr := s.observe(dir, line); lerr != nil {
				return fmt.Errorf("audit log failed, stopping session (fail closed): %w", lerr)
			}
			if _, werr := dst.Write(line); werr != nil {
				return werr
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

// readLine reads up to and including '\n', refusing lines longer than limit.
// bufio.Scanner is the usual tool, but its default 64 KiB limit silently
// breaks large tool results - a classic MCP-proxy bug.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > limit {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(buf) > 0 && buf[len(buf)-1] != '\n' {
			buf = append(buf, '\n') // final message without newline: still frame it
		}
		return buf, err
	}
}

func (s *Session) observe(dir Direction, line []byte) error {
	m := jsonrpc.Parse(line)
	e := audit.Entry{
		Time:    s.now().UTC(),
		Session: s.ID,
		Dir:     string(dir),
		Kind:    string(m.Kind),
		Method:  m.Method,
		ID:      m.ID,
		Tool:    m.ToolName(),
		Bytes:   len(m.Raw),
	}
	if s.LogBodies && json.Valid(m.Raw) {
		e.Body = m.Raw
	}

	switch m.Kind {
	case jsonrpc.KindRequest:
		s.mu.Lock()
		s.pending[string(dir)+":"+string(m.ID)] = pending{m.Method, e.Tool, s.now()}
		s.mu.Unlock()
	case jsonrpc.KindResult, jsonrpc.KindError:
		// A response travels the opposite way to its request, so look it up
		// under the other direction. IDs are only unique per direction.
		key := string(dir.other()) + ":" + string(m.ID)
		s.mu.Lock()
		p, ok := s.pending[key]
		delete(s.pending, key)
		s.mu.Unlock()
		if ok {
			ms := float64(s.now().Sub(p.start).Microseconds()) / 1000
			e.LatencyMS, e.ReplyTo, e.Tool = &ms, p.method, p.tool
		}
		if m.Kind == jsonrpc.KindResult {
			var r struct {
				IsError bool `json:"isError"`
			}
			_ = json.Unmarshal(m.Result, &r)
			e.ToolError = r.IsError
		}
	}
	return s.Log.Write(e)
}
