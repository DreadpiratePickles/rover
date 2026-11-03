//go:build testauth

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/pin"
)

// A `go build -tags testauth` binary, used ONLY by the end-to-end tests and
// the manual demo, takes hidden leading flags:
//
//	rover --test-auth=allow|deny [--test-auth-delay=2s] <command> ...
//
// They replace the OS dialog with a fake that answers as told (and prints
// what the dialog would have said), and the desktop notifier with one that
// prints to stderr. Without --test-auth a testauth build DENIES: it never
// shows a real dialog during a test run. None of this is compiled into a
// production binary.

var testAuth struct {
	answer string
	delay  time.Duration
	flags  []string
}

type fakeAuth struct{}

func (fakeAuth) Authenticate(ctx context.Context, reason string) (bool, string, error) {
	fmt.Fprintf(os.Stderr, "[test-auth] dialog: %s -> %s\n", reason, orDash(testAuth.answer))
	if testAuth.delay > 0 {
		select {
		case <-time.After(testAuth.delay):
		case <-ctx.Done():
			return false, "test", ctx.Err()
		}
	}
	return testAuth.answer == "allow", "test", nil
}

type printNotifier struct{}

func (printNotifier) Notify(title, msg string) {
	fmt.Fprintf(os.Stderr, "[test-notify] %s: %s\n", title, msg)
}

func init() {
	newAuthenticator = func(func(string, ...any)) approve.Authenticator { return fakeAuth{} }
	newNotifier = func(func(string, ...any)) pin.Notifier { return printNotifier{} }
	stripTestFlags = func(args []string) []string {
		for len(args) > 0 {
			switch a := args[0]; {
			case strings.HasPrefix(a, "--test-auth="):
				testAuth.answer = strings.TrimPrefix(a, "--test-auth=")
			case strings.HasPrefix(a, "--test-auth-delay="):
				d, err := time.ParseDuration(strings.TrimPrefix(a, "--test-auth-delay="))
				if err != nil {
					fmt.Fprintln(os.Stderr, "bad --test-auth-delay:", err)
					os.Exit(2)
				}
				testAuth.delay = d
			default:
				return args
			}
			testAuth.flags = append(testAuth.flags, args[0])
			args = args[1:]
		}
		return args
	}
	daemonExtraArgs = func() []string { return testAuth.flags }
}
