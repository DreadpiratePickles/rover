package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// fakeDecider answers from a script: one verdict per message, in order.
type fakeDecider struct {
	mu       sync.Mutex
	seq      uint64
	verdicts []ipc.Frame
	releases map[uint64]chan ipc.Frame
	seen     [][]byte
	err      error
}

func (f *fakeDecider) Decide(_ string, raw []byte) (ipc.Frame, <-chan ipc.Frame, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return ipc.Frame{}, nil, f.err
	}
	f.seq++
	f.seen = append(f.seen, append([]byte{}, raw...))
	v := ipc.Frame{Type: ipc.TypeVerdict, Seq: f.seq, Action: ipc.ActionForward}
	if len(f.verdicts) > 0 {
		v, f.verdicts = f.verdicts[0], f.verdicts[1:]
		v.Seq = f.seq
	}
	if v.Action == ipc.ActionHold {
		if f.releases == nil {
			f.releases = map[uint64]chan ipc.Frame{}
		}
		ch := make(chan ipc.Frame, 1)
		f.releases[f.seq] = ch
		return v, ch, nil
	}
	return v, nil, nil
}

func (f *fakeDecider) release(seq uint64, action string) {
	f.mu.Lock()
	ch := f.releases[seq]
	f.mu.Unlock()
	ch <- ipc.Frame{Type: ipc.TypeRelease, Seq: seq, Action: action, Reason: "test"}
}

// The gateway must forward exactly the bytes it received.
func TestPumpForwardsBytesExactly(t *testing.T) {
	// Odd-but-valid JSON: spacing, key order, unicode escape, big number.
	in := `{"id":1, "jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"café","n":12345678901234567890}}}` + "\n"
	var out, back bytes.Buffer
	w := New(&fakeDecider{})
	if err := w.Pump(strings.NewReader(in), &out, &back, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if out.String() != in {
		t.Fatalf("forwarded bytes changed:\n got %q\nwant %q", out.String(), in)
	}
	if back.Len() != 0 {
		t.Fatalf("nothing should be written back on forward: %q", back.String())
	}
}

func TestEveryMessageIsDecidedBeforeForwarding(t *testing.T) {
	in := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\"}\n\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"b\"}\n"
	d := &fakeDecider{}
	w := New(d)
	var out bytes.Buffer
	if err := w.Pump(strings.NewReader(in), &out, io.Discard, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if len(d.seen) != 2 {
		t.Fatalf("roverd saw %d messages, want 2 (blank lines are not messages)", len(d.seen))
	}
}

func TestBlockedRequestGetsErrorOnItsOwnSide(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"rm"}}` + "\n"
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionBlock, Reason: "policy", RuleIDs: []string{"r1"}}}}
	var out, back bytes.Buffer
	w := New(d)
	if err := w.Pump(strings.NewReader(in), &out, &back, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("blocked request must not reach the server: %q", out.String())
	}
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				RuleIDs []string `json:"rule_ids"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(back.Bytes(), &resp); err != nil {
		t.Fatalf("bad error response %q: %v", back.String(), err)
	}
	if string(resp.ID) != `"abc"` || resp.Error.Code != BlockedErrorCode || !strings.Contains(resp.Error.Message, "policy") || resp.Error.Data.RuleIDs[0] != "r1" {
		t.Fatalf("unexpected error response: %+v", resp)
	}
}

func TestBlockedRequestGetsRoverdResponseRaw(t *testing.T) {
	for name, raw := range map[string]string{
		"without newline": `{"jsonrpc":"2.0","id":7,"result":{"content":[],"isError":true}}`,
		"with newline":    `{"jsonrpc":"2.0","id":7,"result":{"content":[],"isError":true}}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			// Arrange
			in := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file"}}` + "\n"
			d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionBlock, Reason: "forbid x", ResponseRaw: []byte(raw)}}}
			var out, back bytes.Buffer

			// Act
			err := New(d).Pump(strings.NewReader(in), &out, &back, ClientToServer)

			// Assert
			if err != nil {
				t.Fatal(err)
			}
			if out.Len() != 0 {
				t.Fatalf("blocked request reached the server: %q", out.String())
			}
			want := strings.TrimSuffix(raw, "\n") + "\n"
			if back.String() != want {
				t.Fatalf("back = %q, want exactly %q", back.String(), want)
			}
		})
	}
}

func TestBlockedNotificationIsDropped(t *testing.T) {
	in := `{"jsonrpc":"2.0","method":"notifications/x"}` + "\n"
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionBlock}}}
	var out, back bytes.Buffer
	if err := New(d).Pump(strings.NewReader(in), &out, &back, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || back.Len() != 0 {
		t.Fatalf("dropped notification wrote something: out=%q back=%q", out.String(), back.String())
	}
}

func TestReplaceWritesReplacement(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"result":{"secret":"hunter2"}}` + "\n"
	rep := []byte(`{"jsonrpc":"2.0","id":1,"result":{"secret":"[redacted]"}}`)
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionReplace, ReplacementRaw: rep}}}
	var out bytes.Buffer
	if err := New(d).Pump(strings.NewReader(in), &out, io.Discard, ServerToClient); err != nil {
		t.Fatal(err)
	}
	if out.String() != string(rep)+"\n" {
		t.Fatalf("got %q", out.String())
	}
}

// A hold must not block the pipe: later messages keep flowing, and the held
// one is forwarded when released.
func TestHoldDoesNotBlockLaterMessages(t *testing.T) {
	first := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email"}}` + "\n"
	second := `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionHold}}}
	buf := &bytes.Buffer{}
	out := &LockedWriter{W: buf}
	w := New(d)
	if err := w.Pump(strings.NewReader(first+second), out, io.Discard, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != second {
		t.Fatalf("second message should flow while first is held; got %q", got)
	}
	d.release(1, ipc.ActionForward)
	w.Wait()
	if got := buf.String(); got != second+first {
		t.Fatalf("held message not forwarded after release; got %q", got)
	}
}

func TestRejectsOversizedMessage(t *testing.T) {
	w := New(&fakeDecider{})
	w.MaxMessage = 1024
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 5000) + `"}}` + "\n"
	err := w.Pump(strings.NewReader(big), io.Discard, io.Discard, ServerToClient)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

// Messages bigger than bufio.Scanner's 64 KiB default must still pass.
func TestLargeMessageUnderLimitPasses(t *testing.T) {
	var out bytes.Buffer
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 200_000) + `"}}` + "\n"
	if err := New(&fakeDecider{}).Pump(strings.NewReader(big), &out, io.Discard, ServerToClient); err != nil {
		t.Fatal(err)
	}
	if out.Len() != len(big) {
		t.Fatalf("forwarded %d bytes, want %d", out.Len(), len(big))
	}
}

// If roverd cannot be asked, nothing is forwarded (fail closed).
func TestFailsClosedWithoutVerdict(t *testing.T) {
	var out bytes.Buffer
	w := New(&fakeDecider{err: errors.New("socket gone")})
	err := w.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, io.Discard, ClientToServer)
	if err == nil || out.Len() != 0 {
		t.Fatalf("expected failure and nothing forwarded; err=%v forwarded=%q", err, out.String())
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: "allow-ish"}}}
	err := New(d).Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), io.Discard, io.Discard, ClientToServer)
	if err == nil {
		t.Fatal("an action the wrapper does not understand must stop the session")
	}
}
