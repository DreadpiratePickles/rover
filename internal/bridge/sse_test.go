package bridge

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func readAll(t *testing.T, src string, limit int) ([]Event, error) {
	t.Helper()
	r := NewSSEReader(strings.NewReader(src), limit)
	var out []Event
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, ev)
	}
}

func TestSSEParse(t *testing.T) {
	src := ": keep-alive\n" +
		"id: 1\ndata:\n\n" + // the priming event: an id, empty data
		"event: message\r\nid: 2\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n" +
		"retry: 250\n\n" +
		"id: bad\x00id\ndata: x\n\n" + // an id with NUL is ignored
		"data: unterminated" // never dispatched
	evs, err := readAll(t, src, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 4 {
		t.Fatalf("got %d events: %+v", len(evs), evs)
	}
	if evs[0].ID != "1" || len(evs[0].Data) != 0 {
		t.Errorf("priming event: %+v", evs[0])
	}
	if evs[1].ID != "2" || string(evs[1].Data) != "{\"a\":\n1}" || evs[1].Type != "message" {
		t.Errorf("multi-line event: %+v", evs[1])
	}
	if evs[2].Retry != 250*time.Millisecond {
		t.Errorf("retry: %+v", evs[2])
	}
	if evs[3].ID != "2" || string(evs[3].Data) != "x" {
		t.Errorf("an invalid id must keep the last good one: %+v", evs[3])
	}
	line, err := oneLine(evs[1].Data)
	if err != nil || string(line) != `{"a": 1}` {
		t.Errorf("oneLine = %q, %v", line, err)
	}
	if _, err := oneLine([]byte("not\njson")); err == nil {
		t.Error("multi-line non-JSON must be refused")
	}
}

// The data cap holds across many data lines and within one endless line.
func TestSSECap(t *testing.T) {
	many := strings.Repeat("data: 0123456789\n", 20) + "\n"
	if _, err := readAll(t, many, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("many data lines: %v", err)
	}
	long := "data: " + strings.Repeat("x", 500) + "\n\n"
	if _, err := readAll(t, long, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one long line: %v", err)
	}
}

// FuzzSSE: no input makes the reader panic, loop forever, or return data
// over the cap.
func FuzzSSE(f *testing.F) {
	for _, s := range []string{"data: {}\n\n", "id: 1\ndata:\n\n", "retry: 5\n\n", ":c\n", "data: a\r\ndata: b\r\n\r\n", "event: x\ndata: y\n\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		const limit = 256
		r := NewSSEReader(strings.NewReader(s), limit)
		for i := 0; i < len(s)+2; i++ {
			ev, err := r.Next()
			if err != nil {
				return
			}
			if len(ev.Data) > limit || len(ev.ID) > maxEventID || (ev.ID != "" && !headerSafe(ev.ID)) {
				t.Fatalf("event over limits: %d bytes, id %q", len(ev.Data), ev.ID)
			}
			if line, err := oneLine(ev.Data); err == nil && strings.ContainsAny(string(line), "\r\n") {
				t.Fatalf("oneLine left a newline: %q", line)
			}
		}
		t.Fatal("more events than input bytes")
	})
}
