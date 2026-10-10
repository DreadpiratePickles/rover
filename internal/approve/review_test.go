package approve

import (
	"context"
	"strings"
	"testing"
)

// Review M9 MEDIUM-2: three holds at once must be told apart in the dialog.
func TestDialogTextCarriesTheApprovalID(t *testing.T) {
	r := Request{ID: "a1b2c3d4-0000-4000-8000-000000000000", Client: "claude-code", Server: "github", Tool: "push_files"}
	if got := DialogText(r); got != "Rover [a1b2c3d4]: allow claude-code to run github.push_files?" {
		t.Fatalf("%q", got)
	}
}

func TestNotificationCarriesIDAndListCommand(t *testing.T) {
	f, _, n := flow(&fakeAuth{ok: true}, nil)
	r := request()
	_, _ = f.Prompt(context.Background(), r)
	if len(n.msgs) != 1 || !strings.Contains(n.msgs[0], "["+r.ID[:8]+"]") || !strings.Contains(n.msgs[0], "rover approvals list") {
		t.Fatalf("%q", n.msgs)
	}
}

// Review M9 MEDIUM-3 and LOW: why a hold was cancelled is recorded.
func TestCancelCauseIsRecorded(t *testing.T) {
	for cause, want := range map[error]string{ErrWrapperGone: StateWrapperGone, ErrCancelledByClient: StateCancelled} {
		f, st, _ := flow(&fakeAuth{release: make(chan struct{})}, nil)
		r := request()
		ctx, cancel := context.WithCancelCause(context.Background())
		done := make(chan Decision, 1)
		go func() { d, _ := f.Prompt(ctx, r); done <- d }()
		for i := 0; ; i++ { // wait until the record exists
			if _, ok, _ := st.Get(r.ID); ok {
				break
			}
		}
		cancel(cause)
		d := <-done
		rec, _, _ := st.Get(r.ID)
		if d.Allow || rec.State != want || rec.Method != want {
			t.Errorf("%v: decision %+v record %s/%s", cause, d, rec.State, rec.Method)
		}
	}
}

// Review M9 LOW: more invisible characters are stripped.
func TestCleanStripsMoreInvisibles(t *testing.T) {
	for _, r := range []string{"\u061c", "\u200b", "\u200c", "\u200d", "\ufeff"} {
		if got := Clean("a" + r + "b"); got != "ab" {
			t.Errorf("%U: %q", []rune(r)[0], got)
		}
	}
}
