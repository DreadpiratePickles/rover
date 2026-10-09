// Package framing reads newline-delimited messages with a hard size limit.
//
// Both MCP stdio and the wrapper-to-roverd protocol are "one JSON object per
// line". bufio.Scanner is the obvious tool and the wrong one: its default
// 64 KiB limit silently breaks large tool results, and raising it to "big
// enough" invites a hostile peer to send one endless line and exhaust memory.
// ReadLine keeps the cap explicit and fails loudly when it is hit.
package framing

import (
	"bufio"
	"errors"
	"io"
)

// ErrTooLarge is returned when a single line exceeds the caller's limit.
var ErrTooLarge = errors.New("message exceeds size limit")

// ReadLine reads up to and including '\n', refusing lines longer than limit.
// A final line without a trailing newline is still returned, with a newline
// appended, so callers always see framed messages. At EOF it returns the
// remaining bytes (possibly none) together with io.EOF.
func ReadLine(r *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > limit {
			return nil, ErrTooLarge
		}
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(buf) > 0 && buf[len(buf)-1] != '\n' {
			buf = append(buf, '\n')
		}
		return buf, err
	}
}
