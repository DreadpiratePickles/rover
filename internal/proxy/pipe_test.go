package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// fakeDecider returns a fixed verdict (or error) and records what it saw.
type fakeDecider struct {
	mu      sync.Mutex
	verdict Verdict
	err     error
	seen    []string
}

func (f *fakeDecider) Decide(dir Direction, raw []byte) (Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, string(dir)+" "+string(raw))
	return f.verdict, f.err
}

func newPipe(d Decider) (*Pipe, *bytes.Buffer, *bytes.Buffer) {
	var toServer, toClient bytes.Buffer
	return &Pipe{ToServer: &toServer, ToClient: &toClient, Decider: d}, &toServer, &toClient
}

// The gateway must forward exactly the bytes it received, even though the
// decider is handed a trimmed copy.
func TestPipeForwardKeepsExactBytes(t *testing.T) {
	in := `  {"id":1, "jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"café","n":12345678901234567890}}}` + "\n"
	d := &fakeDecider{verdict: Verdict{Action: ActionForward, ReplacementRaw: []byte(`{"ignored":true}`)}}
	p, toServer, toClient := newPipe(d)
	if err := p.Pump(strings.NewReader(in), ClientToServer); err != nil {
		t.Fatal(err)
	}
	if toServer.String() != in {
		t.Fatalf("forwarded bytes changed:\n got %q\nwant %q", toServer.String(), in)
	}
	if toClient.Len() != 0 {
		t.Fatalf("nothing should go back to the client, got %q", toClient.String())
	}
	if want := "c2s " + strings.TrimSpace(in); len(d.seen) != 1 || d.seen[0] != want {
		t.Fatalf("decider saw %q, want %q", d.seen, want)
	}
}

func TestPipeS2CForwardGoesToClient(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	p, toServer, toClient := newPipe(&fakeDecider{verdict: Verdict{Action: ActionForward}})
	if err := p.Pump(strings.NewReader(in), ServerToClient); err != nil {
		t.Fatal(err)
	}
	if toClient.String() != in || toServer.Len() != 0 {
		t.Fatalf("toClient=%q toServer=%q", toClient.String(), toServer.String())
	}
}

func TestPipeReplaceWritesReplacement(t *testing.T) {
	repl := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"}}`
	p, toServer, toClient := newPipe(&fakeDecider{verdict: Verdict{Action: ActionReplace, ReplacementRaw: []byte(repl)}})
	if err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evil"}}`+"\n"), ClientToServer); err != nil {
		t.Fatal(err)
	}
	if toServer.String() != repl+"\n" || toClient.Len() != 0 {
		t.Fatalf("toServer=%q toClient=%q", toServer.String(), toClient.String())
	}
}

// A blocked request is answered (to the sender only); the receiver sees nothing.
func TestPipeBlockWithReplacementRepliesToSender(t *testing.T) {
	reply := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"blocked by rover"}}`
	for _, tc := range []struct {
		dir             Direction
		wantTo, wantNot string
	}{
		{ClientToServer, "client", "server"},
		{ServerToClient, "server", "client"},
	} {
		t.Run(string(tc.dir), func(t *testing.T) {
			p, toServer, toClient := newPipe(&fakeDecider{verdict: Verdict{Action: ActionBlock, ReplacementRaw: []byte(reply), Reason: "test"}})
			if err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"x"}`+"\n"), tc.dir); err != nil {
				t.Fatal(err)
			}
			got := map[string]string{"server": toServer.String(), "client": toClient.String()}
			if got[tc.wantTo] != reply+"\n" || got[tc.wantNot] != "" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

func TestPipeBlockWithoutReplacementDrops(t *testing.T) {
	p, toServer, toClient := newPipe(&fakeDecider{verdict: Verdict{Action: ActionBlock}})
	if err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/x"}`+"\n"), ClientToServer); err != nil {
		t.Fatal(err)
	}
	if toServer.Len() != 0 || toClient.Len() != 0 {
		t.Fatalf("toServer=%q toClient=%q", toServer.String(), toClient.String())
	}
}

// Every way of "not understanding" the decision stops the session with
// nothing written (fail closed).
func TestPipeFailsClosed(t *testing.T) {
	cases := map[string]*fakeDecider{
		"hold":                 {verdict: Verdict{Action: ActionHold}},
		"unknown action":       {verdict: Verdict{Action: "allow-ish"}},
		"empty action":         {verdict: Verdict{}},
		"decide error":         {verdict: Verdict{Action: ActionForward}, err: errors.New("roverd went away")},
		"replace empty":        {verdict: Verdict{Action: ActionReplace}},
		"replace with newline": {verdict: Verdict{Action: ActionReplace, ReplacementRaw: []byte("{}\n{}")}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			p, toServer, toClient := newPipe(d)
			err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), ClientToServer)
			if !errors.Is(err, ErrStopped) {
				t.Fatalf("want ErrStopped, got %v", err)
			}
			if toServer.Len() != 0 || toClient.Len() != 0 {
				t.Fatalf("wrote something: toServer=%q toClient=%q", toServer.String(), toClient.String())
			}
		})
	}
}

// After a stop, later messages are not read or forwarded either.
func TestPipeStopsAtFirstFailure(t *testing.T) {
	d := &fakeDecider{verdict: Verdict{Action: ActionHold}}
	p, toServer, _ := newPipe(d)
	in := `{"jsonrpc":"2.0","id":1,"method":"a"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"b"}` + "\n"
	if err := p.Pump(strings.NewReader(in), ClientToServer); err == nil {
		t.Fatal("expected an error")
	}
	if len(d.seen) != 1 || toServer.Len() != 0 {
		t.Fatalf("seen=%q forwarded=%q", d.seen, toServer.String())
	}
}

func TestPipeRejectsOversizedMessage(t *testing.T) {
	d := &fakeDecider{verdict: Verdict{Action: ActionForward}}
	p, toServer, toClient := newPipe(d)
	p.MaxMessage = 1024
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 5000) + `"}}` + "\n"
	err := p.Pump(strings.NewReader(big), ServerToClient)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
	if len(d.seen) != 0 || toServer.Len() != 0 || toClient.Len() != 0 {
		t.Fatal("an oversized message must not reach the decider or either side")
	}
}

// Messages bigger than bufio.Scanner's 64 KiB default must still pass.
func TestPipeLargeMessageUnderLimitPasses(t *testing.T) {
	p, _, toClient := newPipe(&fakeDecider{verdict: Verdict{Action: ActionForward}})
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 200_000) + `"}}` + "\n"
	if err := p.Pump(strings.NewReader(big), ServerToClient); err != nil {
		t.Fatal(err)
	}
	if toClient.String() != big {
		t.Fatalf("forwarded %d bytes, want %d", toClient.Len(), len(big))
	}
}

// A final message without a trailing newline is still framed with one.
func TestPipeFramesFinalLineWithoutNewline(t *testing.T) {
	p, toServer, _ := newPipe(&fakeDecider{verdict: Verdict{Action: ActionForward}})
	if err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","method":"x"}`), ClientToServer); err != nil {
		t.Fatal(err)
	}
	if toServer.String() != `{"jsonrpc":"2.0","method":"x"}`+"\n" {
		t.Fatalf("got %q", toServer.String())
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestPipeWriteErrorStops(t *testing.T) {
	p := &Pipe{ToServer: brokenWriter{}, ToClient: io.Discard, Decider: &fakeDecider{verdict: Verdict{Action: ActionForward}}}
	if err := p.Pump(strings.NewReader(`{"jsonrpc":"2.0","method":"x"}`+"\n"), ClientToServer); err == nil {
		t.Fatal("expected the write error")
	}
}

// lineWriter fails the test if a single Write call holds anything but whole
// lines, which is what happens if two pumps interleave their writes.
type lineWriter struct {
	t     *testing.T
	mu    sync.Mutex
	lines int
}

func (w *lineWriter) Write(b []byte) (int, error) {
	if !bytes.HasSuffix(b, []byte("\n")) || bytes.Count(b, []byte("\n")) != 1 {
		w.t.Errorf("partial or merged write: %q", b)
	}
	w.mu.Lock()
	w.lines++
	w.mu.Unlock()
	return len(b), nil
}

// Both pumps run at once and both write to the client (s2c forwards, c2s
// block replies). Run under -race, this checks the per-writer locks.
func TestPipeBothDirectionsConcurrently(t *testing.T) {
	client := &lineWriter{t: t}
	d := deciderFunc(func(dir Direction, _ []byte) (Verdict, error) {
		if dir == ClientToServer {
			return Verdict{Action: ActionBlock, ReplacementRaw: []byte(`{"jsonrpc":"2.0","id":0,"error":{"code":-1,"message":"no"}}`)}, nil
		}
		return Verdict{Action: ActionForward}, nil
	})
	p := &Pipe{ToServer: io.Discard, ToClient: client, Decider: d}
	var reqs, resps strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&reqs, `{"jsonrpc":"2.0","id":%d,"method":"ping"}`+"\n", i)
		fmt.Fprintf(&resps, `{"jsonrpc":"2.0","id":%d,"result":{}}`+"\n", i)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.Pump(strings.NewReader(reqs.String()), ClientToServer); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.Pump(strings.NewReader(resps.String()), ServerToClient); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	if client.lines != 1000 {
		t.Fatalf("client got %d lines, want 1000", client.lines)
	}
}

type deciderFunc func(Direction, []byte) (Verdict, error)

func (f deciderFunc) Decide(dir Direction, raw []byte) (Verdict, error) { return f(dir, raw) }
