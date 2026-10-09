package pin

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
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
	return "Rover blocked a tool", fmt.Sprintf("%s/%s: %s. Review with `rover pin list %s`.", e.Server, e.Tool, what, e.Server)
}
