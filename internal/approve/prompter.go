package approve

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Clock is the time source of a Flow; tests inject a fake one so the
// timeout is exercised without waiting two minutes.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// RealClock is the wall clock.
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now() }

// After implements Clock.
func (RealClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Notifier shows a desktop notification (pin.OSNotifier implements it).
type Notifier interface {
	Notify(title, message string)
}

// Pages registers a request with the read-only details page and returns
// the URL to put in the notification.
type Pages interface {
	Register(r Request) (url string, err error)
}

// Flow is the Prompter roverd uses (plan M9 Flow 1-5):
//
//  1. record the approval as pending;
//  2. if the client supports elicitation, ask it there too (a decline
//     denies; an accept does NOT approve, it only means "now show me the
//     dialog");
//  3. send a desktop notification with the details page URL;
//  4. show the OS authentication dialog: success forwards, anything else
//     denies;
//  5. no answer before the timeout denies.
//
// Every failure along the way is a deny (fail closed).
type Flow struct {
	Store    Store
	Auth     Authenticator
	Notifier Notifier
	Pages    Pages // nil: no details page (the notification says so)
	Clock    Clock
	Timeout  time.Duration
	Logf     func(format string, a ...any)

	override atomic.Int64 // SetTimeout, nanoseconds
}

// SetTimeout replaces Timeout for approvals started from now on (roverd
// calls it when config.yaml's approvals.timeout_s changes on reload).
func (f *Flow) SetTimeout(d time.Duration) { f.override.Store(int64(d)) }

type answer struct {
	allow  bool
	method string
	reason string
}

// Prompt implements Prompter. It returns once the call is decided; the
// error is only about bookkeeping (the record could not be written), and
// the decision is a deny whenever it is set.
func (f *Flow) Prompt(ctx context.Context, r Request) (Decision, error) {
	clock, timeout, logf := f.clock(), f.timeout(), f.logf()
	r.Created = clock.Now().UTC()
	r.Deadline = r.Created.Add(timeout)
	if err := f.Store.Put(Record{Request: r, State: StatePending}); err != nil {
		// No record, no approval: a call nobody can audit is not approved.
		return Decision{Reason: ReasonDenied, Method: "record_failed"}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	answers := make(chan answer, 2)
	if r.Elicitor != nil {
		go f.elicit(ctx, r, answers)
	}
	f.notify(r)
	go f.authenticate(ctx, r, answers)

	var a answer
	select {
	case a = <-answers:
	case <-clock.After(timeout):
		a = answer{method: "timeout", reason: ReasonTimedOut}
	case <-ctx.Done():
		a = answer{method: "cancelled", reason: ReasonDenied}
	}
	cancel() // closes the dialog and forgets the elicitation
	d := Decision{Allow: a.allow, Method: a.method, Reason: a.reason}
	st := StateDenied
	switch {
	case d.Allow:
		st = StateAllowed
	case d.Reason == ReasonTimedOut:
		st = StateTimedOut
	}
	rec := Record{Request: r, State: st, Method: d.Method, Reason: d.Reason, DecidedAt: clock.Now().UTC()}
	if err := f.Store.Put(rec); err != nil {
		logf("approval %s: recording the decision failed: %v; denying", r.ID, err)
		return Decision{Reason: ReasonDenied, Method: d.Method}, err
	}
	logf("approval %s: %s %s.%s for %s (%s)", r.ID, st, Clean(r.Server), Clean(r.Tool), Clean(orUnknown(r.Client)), d.Method)
	return d, nil
}

// elicit asks the agent app. Only a decline answers; an accept or an
// error leaves the decision to the OS dialog.
func (f *Flow) elicit(ctx context.Context, r Request, out chan<- answer) {
	accepted, err := r.Elicitor.Elicit(ctx, r)
	switch {
	case err != nil:
		if !errors.Is(err, context.Canceled) {
			f.logf()("approval %s: elicitation failed: %v (the OS dialog still decides)", r.ID, err)
		}
	case !accepted:
		out <- answer{method: "elicitation", reason: ReasonDenied}
	}
}

func (f *Flow) authenticate(ctx context.Context, r Request, out chan<- answer) {
	if f.Auth == nil {
		out <- answer{method: "none", reason: ReasonDenied}
		return
	}
	ok, method, err := f.Auth.Authenticate(ctx, DialogText(r))
	switch {
	case ok && err == nil:
		out <- answer{allow: true, method: method}
	case errors.Is(err, ErrNotInteractive):
		f.logf()("approval %s: denied: %s", r.ID, ReasonNotInteractive)
		out <- answer{method: "not_interactive", reason: ReasonDenied}
	case errors.Is(err, ErrNoAuthAgent):
		f.logf()("approval %s: denied: %s (no authentication agent; on Linux run a polkit agent, see `rover install --polkit`)", r.ID, ReasonNoAuthAgent)
		out <- answer{method: ReasonNoAuthAgent, reason: ReasonDenied}
	default:
		if err != nil && !errors.Is(err, context.Canceled) {
			f.logf()("approval %s: authentication failed: %v", r.ID, err)
		}
		out <- answer{method: method, reason: ReasonDenied}
	}
}

// notify sends the desktop notification. One line, lower case, no
// exclamation marks (plan §4.7); the URL first so a truncated
// notification still carries it.
func (f *Flow) notify(r Request) {
	if f.Notifier == nil {
		return
	}
	where := "no details page"
	if f.Pages != nil {
		url, err := f.Pages.Register(r)
		if err != nil {
			f.logf()("approval %s: details page: %v", r.ID, err)
		} else {
			where = url
		}
	}
	f.Notifier.Notify("rover: approval needed",
		where+" "+Clean(orUnknown(r.Client))+" wants to run "+Clean(r.Server)+"."+Clean(r.Tool))
}

func (f *Flow) clock() Clock {
	if f.Clock == nil {
		return RealClock{}
	}
	return f.Clock
}

func (f *Flow) timeout() time.Duration {
	if d := time.Duration(f.override.Load()); d > 0 {
		return d
	}
	if f.Timeout <= 0 {
		return DefaultTimeout
	}
	return f.Timeout
}

func (f *Flow) logf() func(string, ...any) {
	if f.Logf == nil {
		return func(string, ...any) {}
	}
	return f.Logf
}
