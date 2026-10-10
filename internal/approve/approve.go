// Package approve is Rover's human in the loop (plan M9, D8, D9).
//
// When the policy says a call needs approval (a permit annotated
// @rover_require("approval")), roverd holds the call and runs a Prompter.
// The only thing that can release it with "forward" is the operating
// system's authentication dialog: LocalAuthentication on macOS, polkit on
// Linux. Everything else Rover offers the human (an MCP elicitation in the
// agent app, a desktop notification, a read-only details page) is there to
// inform them, and at most to say no.
//
// LESSON (M9): the agent can click anything it can reach. A web page with an
// "Approve" button on 127.0.0.1 is reachable with curl; a CLI command is
// reachable through the agent's shell tool; a file is reachable through its
// file tools. A dialog drawn by the OS, which asks for the user's
// fingerprint or password, is not: the agent cannot type the password it
// does not know or put a finger on the sensor. That is why approval is an
// OS dialog and nothing else, and why every other surface in this package
// is read-only or can only deny.
package approve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Request is one call waiting for a human.
type Request struct {
	ID      string
	Session string
	Client  string // the agent app's self-reported name (clientInfo)
	Server  string
	Tool    string
	Summary string
	// Args are the call's arguments. M10 will redact secrets from them;
	// until then they are shown only when approvals.show_args is true,
	// and never written to disk.
	Args     json.RawMessage
	RuleIDs  []string
	Created  time.Time
	Deadline time.Time
	// Elicitor asks the agent app (MCP elicitation) when the client
	// advertised the capability; nil otherwise. Not part of the record.
	Elicitor Elicitor `json:"-"`
}

// Decision is the outcome of one approval.
type Decision struct {
	Allow  bool
	Method string // how the human answered: an Authenticator method, "elicitation", "timeout"
	Reason string // for a deny: ReasonDenied, ReasonTimedOut, ...
}

// Authenticator proves a human is present: the OS authentication dialog.
// ok is true only when the user authenticated. An error always comes with
// ok false.
type Authenticator interface {
	Authenticate(ctx context.Context, reason string) (ok bool, method string, err error)
}

// Prompter runs the whole approval flow for one held call.
type Prompter interface {
	Prompt(ctx context.Context, r Request) (Decision, error)
}

// Elicitor sends an MCP elicitation/create to the agent app and waits for
// the answer. accepted false means the user declined or cancelled.
type Elicitor interface {
	Elicit(ctx context.Context, r Request) (accepted bool, err error)
}

// Reasons a held call is refused; they end up in the §5.1 isError body.
const (
	ReasonDenied   = "approval denied"
	ReasonTimedOut = "approval timed out"
	// ReasonNoAuthAgent is logged when Linux has no polkit agent to show
	// the dialog (a headless machine): the call is denied.
	ReasonNoAuthAgent = "no_auth_agent"
)

// Approval states in the approvals bucket.
const (
	StatePending  = "pending"
	StateAllowed  = "allowed"
	StateDenied   = "denied"
	StateTimedOut = "timed_out"
)

// ErrNoAuthAgent is returned by an Authenticator that has nobody to ask.
var ErrNoAuthAgent = errors.New(ReasonNoAuthAgent)

// ErrNotInteractive is returned when the OS refuses to show a dialog for
// this process (macOS LAErrorNotInteractive, -1004): roverd, started in
// the background, may be such a process. It is a deny.
var ErrNotInteractive = errors.New(ReasonNotInteractive)

// ReasonNotInteractive is what a deny for ErrNotInteractive says.
const ReasonNotInteractive = "no interactive authentication from the daemon; see the spike notes"

// ErrUnsupported is returned where Rover has no OS dialog (it denies).
var ErrUnsupported = errors.New("no OS authentication on this platform")

// DefaultTimeout is how long a held call waits (config approvals.timeout_s).
const DefaultTimeout = 120 * time.Second

// maxText caps one piece of server-controlled text in a dialog or page.
const maxText = 120

// DialogText is the reason string the OS dialog shows (plan M9 Flow 4).
// Server and tool names come from the server, so they are cleaned.
func DialogText(r Request) string {
	s := fmt.Sprintf("Rover: allow %s to run %s.%s", Clean(orUnknown(r.Client)), Clean(r.Server), Clean(r.Tool))
	if r.Summary != "" {
		s += " (" + Clean(r.Summary) + ")"
	}
	return s + "?"
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown client"
	}
	return s
}

// Clean makes text from a server safe for a dialog, notification or log
// line: control characters become spaces, the length is capped, invalid
// UTF-8 is replaced.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		// Bidi controls can make text read backwards in a dialog.
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxText {
		s = string(r[:maxText]) + "..."
	}
	return s
}

// NewID returns a random UUID (version 4), the approval id.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ValidID reports whether s is a lowercase UUID as NewID makes them.
func ValidID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// NewToken returns 128 random bits as 32 hex digits.
func NewToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
