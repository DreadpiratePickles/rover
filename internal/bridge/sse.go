package bridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/DreadpiratePickles/rover/internal/framing"
)

// LESSON (M11): Server-Sent Events is a text format a hostile server fully
// controls, so the reader is written like every other Rover parser: one
// line at a time through framing.ReadLine with a hard cap, and an event's
// data capped at the same 16 MiB as a stdio message. A server that never
// sends a newline, or piles "data:" lines into one endless event, gets
// ErrTooLarge and the stream is dropped, not Rover's memory.

// Event is one dispatched SSE event.
type Event struct {
	Type  string        // "event:" field; "" means the default, "message"
	Data  []byte        // "data:" lines joined by "\n"; nil for a data-less event
	ID    string        // last event id after this event (SSE keeps it across events)
	Retry time.Duration // "retry:" if this event carried one, else 0
}

// maxEventID bounds an event id: it is sent back in a Last-Event-ID header.
const maxEventID = 1024

// SSEReader parses a text/event-stream (WHATWG HTML §9.2.6). Lines end with
// "\n" or "\r\n"; a bare "\r" terminator is not supported and makes the
// stream look like one long line, which the cap ends.
type SSEReader struct {
	r      *bufio.Reader
	max    int
	lastID string
	done   bool
}

// NewSSEReader reads events from r with data capped at limit bytes per event.
func NewSSEReader(r io.Reader, limit int) *SSEReader {
	return &SSEReader{r: bufio.NewReaderSize(r, 64<<10), max: limit}
}

// LastID is the last event id seen, for Last-Event-ID on reconnect.
func (s *SSEReader) LastID() string { return s.lastID }

// Next returns the next event that carries data or a retry. It returns
// io.EOF at the end of the stream; an unterminated final event is
// discarded, as the SSE standard says.
func (s *SSEReader) Next() (Event, error) {
	var ev Event
	var data bytes.Buffer
	hasData := false
	for {
		if s.done {
			return Event{}, io.EOF
		}
		// A field name and "data: " add a little to the data cap.
		line, err := framing.ReadLine(s.r, s.max+64)
		if err != nil && !errors.Is(err, io.EOF) {
			return Event{}, err
		}
		if errors.Is(err, io.EOF) {
			// An unterminated last line, and an event never closed by a
			// blank line, are discarded, as the SSE standard says.
			s.done = true
			return Event{}, io.EOF
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(line) == 0 {
			ev.ID = s.lastID
			if hasData || ev.Retry > 0 {
				if hasData {
					ev.Data = append([]byte{}, data.Bytes()...)
				}
				return ev, nil
			}
			ev, data, hasData = Event{}, bytes.Buffer{}, false
			continue
		}
		if line[0] == ':' {
			continue // a comment (keep-alive)
		}
		name, value := splitField(line)
		switch name {
		case "data":
			if hasData {
				data.WriteByte('\n')
			}
			if data.Len()+len(value) > s.max {
				return Event{}, fmt.Errorf("sse event data: %w", framing.ErrTooLarge)
			}
			data.Write(value)
			hasData = true
		case "event":
			ev.Type = string(value)
		case "id":
			if len(value) <= maxEventID && headerSafe(string(value)) {
				s.lastID = string(value) // ids with NUL or control bytes are ignored
			}
		case "retry":
			if ms, err := strconv.ParseUint(string(value), 10, 32); err == nil {
				ev.Retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

// splitField splits "name: value" (one optional space after the colon).
func splitField(line []byte) (string, []byte) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return string(line), nil
	}
	v := line[i+1:]
	if len(v) > 0 && v[0] == ' ' {
		v = v[1:]
	}
	return string(line[:i]), v
}

// oneLine turns an SSE data payload or a JSON body into a stdio line (no
// trailing newline). JSON allows newlines only as whitespace between tokens,
// so for valid JSON replacing them with spaces is pure framing and changes
// no value; anything else with a newline in it is refused, because stdio
// cannot carry it as one message.
func oneLine(b []byte) ([]byte, error) {
	b = bytes.TrimRight(b, " \t\r\n")
	b = bytes.TrimLeft(b, " \t\r\n")
	if !bytes.ContainsAny(b, "\r\n") {
		return b, nil
	}
	if !json.Valid(b) {
		return nil, errors.New("a multi-line payload that is not valid JSON cannot be framed for stdio")
	}
	out := bytes.Clone(b)
	for i, c := range out {
		if c == '\n' || c == '\r' {
			out[i] = ' '
		}
	}
	return out, nil
}
