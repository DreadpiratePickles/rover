package pin

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Notifier tells the human that a tool was blocked. It must not block the
// caller for long and its failure is never fatal: the block already happened.
type Notifier interface {
	Notify(title, message string)
}

// NopNotifier does nothing.
type NopNotifier struct{}

// Notify implements Notifier.
func (NopNotifier) Notify(string, string) {}

// notifyTimeout bounds one notification helper process.
const notifyTimeout = 10 * time.Second

// maxNotifyText caps what reaches the notification (names come from the server).
const maxNotifyText = 200

// OSNotifier shows a desktop notification: osascript on macOS, notify-send on
// Linux. The helper runs in the background; errors go to Logf.
// (The plan's richer notifications and approval UI are M9.)
type OSNotifier struct {
	Logf func(string, ...any)
}

// Notify implements Notifier.
func (n OSNotifier) Notify(title, message string) {
	title, message = clean(title), clean(message)
	var cmd []string
	switch runtime.GOOS {
	case "darwin":
		// The text is an AppleScript string literal: with backslash and
		// quote escaped (and controls gone) nothing in it can end the
		// literal and run as script.
		cmd = []string{"osascript", "-e", "display notification " + appleScriptString(message) + " with title " + appleScriptString(title)}
	case "linux":
		cmd = []string{"notify-send", "--", title, message}
	default:
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()
		// G204: a fixed helper binary; the text is passed as one argument
		// (an AppleScript string literal on macOS), never through a shell.
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput() //nolint:gosec // G204: fixed binary, escaped literal argument, see above
		if err != nil && n.Logf != nil {
			n.Logf("desktop notification failed (%s): %v %s", cmd[0], err, strings.TrimSpace(string(out)))
		}
	}()
}

// clean drops control characters and caps the length.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxNotifyText {
		s = s[:maxNotifyText] + "..."
	}
	return strings.ToValidUTF8(s, "?")
}

func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// Message is the notification text for a mismatch event.
func Message(e Event) (title, message string) {
	what := map[string]string{
		KindChanged:      "its definition changed since it was pinned",
		KindNewAfterPins: "the server added it after its tools were pinned",
		KindInvalid:      "its definition is malformed",
	}[e.Kind]
	return notifyTitle, fmt.Sprintf("%s/%s: %s. Review with `rover pin list %s`.", e.Server, e.Tool, what, e.Server)
}

// NotifyWindow is the shortest gap between two notifications for one server.
const NotifyWindow = 10 * time.Second

// Coalescer limits desktop notifications to one per server per NotifyWindow
// (review L4): a server that changes fifty tools, or flaps, must not bury
// the desktop. The first change is shown at once with its own message;
// changes within the window are counted and shown as one "N tools changed
// on <server>" when it ends. Safe for concurrent use.
type Coalescer struct {
	next  Notifier
	now   func() time.Time
	after func(time.Duration, func()) // time.AfterFunc; tests replace it
	count func(server string, n int) string

	mu sync.Mutex
	st map[string]*coalesceState
}

type coalesceState struct {
	last    time.Time
	pending int
	armed   bool
}

// NewCoalescer wraps next; now is the daemon clock.
func NewCoalescer(next Notifier, now func() time.Time) *Coalescer {
	return NewCoalescerWith(next, now, countMessage)
}

// NewCoalescerWith is NewCoalescer with its own "N tools ..." message, for
// events that are not pin changes (detection removing tools, M5).
func NewCoalescerWith(next Notifier, now func() time.Time, count func(server string, n int) string) *Coalescer {
	return &Coalescer{next: next, now: now, st: map[string]*coalesceState{}, count: count,
		after: func(d time.Duration, f func()) { time.AfterFunc(d, f) }}
}

// Add reports n changed tools on server; single is the message to show when
// it can be sent at once and n is 1.
func (c *Coalescer) Add(server string, n int, single string) {
	c.mu.Lock()
	st, ok := c.st[server]
	if !ok {
		st = &coalesceState{}
		c.st[server] = st
	}
	now := c.now()
	if !st.armed && (st.last.IsZero() || now.Sub(st.last) >= NotifyWindow) {
		st.last = now
		c.mu.Unlock()
		if n != 1 || single == "" {
			single = c.count(server, n)
		}
		c.next.Notify(notifyTitle, single)
		return
	}
	st.pending += n
	if !st.armed {
		st.armed = true
		c.after(NotifyWindow-now.Sub(st.last), func() { c.flush(server) })
	}
	c.mu.Unlock()
}

func (c *Coalescer) flush(server string) {
	c.mu.Lock()
	st := c.st[server]
	n := st.pending
	st.pending, st.armed, st.last = 0, false, c.now()
	c.mu.Unlock()
	if n > 0 {
		c.next.Notify(notifyTitle, c.count(server, n))
	}
}

const notifyTitle = "Rover blocked a tool"

func countMessage(server string, n int) string {
	tools := "tools"
	if n == 1 {
		tools = "tool"
	}
	return fmt.Sprintf("%d %s changed on %s. Review with `rover pin list %s`.", n, tools, server, server)
}
