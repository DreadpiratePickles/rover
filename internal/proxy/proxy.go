// Package proxy sits in the middle of an MCP stdio connection.
//
//	agent (Claude Code) --stdin-->    rover     --stdin--> MCP server
//	agent               <--stdout--   rover     <--stdout- MCP server
//
// LESSON (A1): this is a man-in-the-middle, used defensively. Every security
// feature in Track A (policy, pinning, inspection, redaction) is a hook in
// the Pump loop. A1 only observed; A2 starts saying "no".
//
// LESSON (M1): the wrapper no longer decides anything itself. Pipe.Pump (in
// pipe.go) reads one message, asks a Decider (roverd, over a Unix socket)
// what to do with it, and applies the answer. Logging, request/response
// correlation and every later decision live in roverd (internal/daemon).
//
// MCP stdio framing: each message is one line of JSON terminated by "\n",
// and messages must not contain raw newlines.
package proxy

import (
	"bufio"
	"errors"
	"io"
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

// ErrMessageTooLarge is returned when a single message exceeds the limit
// (Pipe.MaxMessage, or the limit passed to ReadLine).
var ErrMessageTooLarge = errors.New("message exceeds size limit")

// ReadLine reads up to and including '\n', refusing lines longer than limit.
// bufio.Scanner is the usual tool, but its default 64 KiB limit silently
// breaks large tool results - a classic MCP-proxy bug.
//
// It is shared by both proxy pumps and by internal/ipc, whose wire format is
// also one JSON object per line. At EOF it returns the last (possibly
// unterminated) line together with io.EOF, framed with a '\n'.
func ReadLine(r *bufio.Reader, limit int) ([]byte, error) {
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
