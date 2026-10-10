package approve

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock fires After only when the test says so.
type fakeClock struct {
	now   time.Time
	fire  chan time.Time
	asked chan time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), fire: make(chan time.Time), asked: make(chan time.Duration, 1)}
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.asked <- d
	return c.fire
}

// fakeAuth answers after release is closed (or at once if nil); it records
// the reason text and whether it was cancelled.
type fakeAuth struct {
	ok       bool
	err      error
	release  chan struct{}
	mu       sync.Mutex
	reason   string
	canceled bool
}

func (a *fakeAuth) Authenticate(ctx context.Context, reason string) (bool, string, error) {
	a.mu.Lock()
	a.reason = reason
	a.mu.Unlock()
	if a.release != nil {
		select {
		case <-a.release:
		case <-ctx.Done():
			a.mu.Lock()
			a.canceled = true
			a.mu.Unlock()
			return false, "fake", ctx.Err()
		}
	}
	return a.ok, "fake", a.err
}

type fakeElicitor struct {
	accepted bool
	err      error
}

func (e fakeElicitor) Elicit(context.Context, Request) (bool, error) { return e.accepted, e.err }

type notes struct {
	mu   sync.Mutex
	msgs []string
}

func (n *notes) Notify(title, msg string) {
	n.mu.Lock()
	n.msgs = append(n.msgs, title+": "+msg)
	n.mu.Unlock()
}

type fakePages struct{}

func (fakePages) Register(r Request) (string, error) {
	return "http://127.0.0.1:1/approval/" + r.ID + "?t=tok", nil
}

func request() Request {
	return Request{ID: NewID(), Session: "s1", Client: "claude-code", Server: "github", Tool: "push_files", Summary: "push to main", Args: []byte(`{"k":"secret"}`)}
}

func flow(auth Authenticator, clock Clock) (*Flow, *MemStore, *notes) {
	st, n := NewMemStore(), &notes{}
	return &Flow{Store: st, Auth: auth, Notifier: n, Pages: fakePages{}, Clock: clock, Timeout: 90 * time.Second}, st, n
}

func TestAuthenticationSuccessAllowsAndIsRecorded(t *testing.T) {
	// Arrange
	auth := &fakeAuth{ok: true}
	f, st, n := flow(auth, nil)
	r := request()

	// Act
	d, err := f.Prompt(context.Background(), r)

	// Assert
	if err != nil || !d.Allow || d.Method != "fake" {
		t.Fatalf("decision %+v, err %v", d, err)
	}
	rec, ok, _ := st.Get(r.ID)
	if !ok || rec.State != StateAllowed || rec.Method != "fake" || rec.DecidedAt.IsZero() || rec.Args != nil {
		t.Fatalf("record %+v", rec)
	}
	if auth.reason != "Rover ["+r.ID[:8]+"]: allow claude-code to run github.push_files (push to main)?" {
		t.Fatalf("dialog text %q", auth.reason)
	}
	if len(n.msgs) != 1 || !strings.Contains(n.msgs[0], "http://127.0.0.1:1/approval/"+r.ID) || strings.Contains(n.msgs[0], "!") {
		t.Fatalf("notification %q", n.msgs)
	}
}

func TestCancelOrFailureDenies(t *testing.T) {
	for name, auth := range map[string]*fakeAuth{
		"cancel":  {ok: false},
		"failure": {ok: false, err: errors.New("LocalAuthentication error -1")},
		"err+ok":  {ok: true, err: errors.New("confused")},
	} {
		f, st, _ := flow(auth, nil)
		r := request()
		d, _ := f.Prompt(context.Background(), r)
		rec, _, _ := st.Get(r.ID)
		if d.Allow || d.Reason != ReasonDenied || rec.State != StateDenied {
			t.Errorf("%s: decision %+v, record %s", name, d, rec.State)
		}
	}
}

func TestTimeoutDeniesWithInjectedClock(t *testing.T) {
	// Arrange: the dialog never answers.
	clock := newFakeClock()
	auth := &fakeAuth{release: make(chan struct{})}
	f, st, _ := flow(auth, clock)
	r := request()
	done := make(chan Decision, 1)

	// Act
	go func() { d, _ := f.Prompt(context.Background(), r); done <- d }()
	if got := <-clock.asked; got != 90*time.Second {
		t.Fatalf("timeout %v, want the configured 90s", got)
	}
	clock.fire <- clock.now.Add(90 * time.Second)
	d := <-done

	// Assert
	rec, _, _ := st.Get(r.ID)
	if d.Allow || d.Reason != ReasonTimedOut || rec.State != StateTimedOut || !rec.Deadline.Equal(clock.now.Add(90*time.Second)) {
		t.Fatalf("decision %+v, record %+v", d, rec)
	}
	for i := 0; ; i++ {
		auth.mu.Lock()
		canceled := auth.canceled
		auth.mu.Unlock()
		if canceled {
			break
		}
		if i == 500 {
			t.Fatal("the dialog must be closed when the approval times out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestElicitationDeclineDeniesAndAcceptStillNeedsTheDialog(t *testing.T) {
	// Arrange
	pending := &fakeAuth{release: make(chan struct{})}
	f, _, _ := flow(pending, nil)
	declined := request()
	declined.Elicitor = fakeElicitor{accepted: false}

	// Act
	d, _ := f.Prompt(context.Background(), declined)

	// Assert
	if d.Allow || d.Method != "elicitation" {
		t.Fatalf("decline: %+v", d)
	}

	// Arrange: accepted in the client, but the OS dialog is cancelled.
	f2, _, _ := flow(&fakeAuth{ok: false}, nil)
	accepted := request()
	accepted.Elicitor = fakeElicitor{accepted: true}

	// Act
	d2, _ := f2.Prompt(context.Background(), accepted)

	// Assert
	if d2.Allow {
		t.Fatalf("an elicitation accept alone must never approve: %+v", d2)
	}
}

func TestNoAuthAgentDenies(t *testing.T) {
	f, _, _ := flow(&fakeAuth{err: ErrNoAuthAgent}, nil)
	var logs []string
	f.Logf = func(format string, _ ...any) { logs = append(logs, format) }
	d, _ := f.Prompt(context.Background(), request())
	if d.Allow || d.Method != ReasonNoAuthAgent || !strings.Contains(strings.Join(logs, "\n"), "no authentication agent") {
		t.Fatalf("decision %+v, logs %q", d, logs)
	}
}

type failingStore struct{ MemStore }

func (*failingStore) Put(Record) error { return errors.New("disk full") }

func TestUnrecordableApprovalIsDenied(t *testing.T) {
	f := &Flow{Store: &failingStore{}, Auth: &fakeAuth{ok: true}}
	d, err := f.Prompt(context.Background(), request())
	if err == nil || d.Allow {
		t.Fatalf("decision %+v, err %v", d, err)
	}
}

func TestDialogTextIsCleaned(t *testing.T) {
	r := Request{Server: "evil", Tool: "x\n\u202eexe.txt", Summary: strings.Repeat("a", 500)}
	got := DialogText(r)
	if strings.ContainsAny(got, "\n\u202e") || !strings.HasPrefix(got, "Rover []: allow an unknown client to run evil.x ") || len(got) > 300 {
		t.Fatalf("%q", got)
	}
}

func TestIDsAndTokens(t *testing.T) {
	id := NewID()
	if !ValidID(id) || ValidID(strings.ToUpper(id)) || ValidID(id[:35]) || ValidID("../"+id[3:]) {
		t.Fatalf("ValidID wrong for %q", id)
	}
	if tok := NewToken(); len(tok) != 32 || tok == NewToken() {
		t.Fatalf("token %q", tok)
	}
}
