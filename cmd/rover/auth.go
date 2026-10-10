package main

import (
	"context"
	"errors"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/pin"
)

// These are the seams a `testauth` build replaces (testauth.go). Production
// code never reads an environment variable or a flag to choose them: an
// agent that could set ROVER_TEST_AUTH=allow would approve its own calls.

// newAuthenticator returns the OS authentication dialog of this platform.
var newAuthenticator = func(logf func(string, ...any)) approve.Authenticator {
	return approve.Platform(logf)
}

// newNotifier returns the desktop notifier.
var newNotifier = func(logf func(string, ...any)) pin.Notifier {
	return pin.OSNotifier{Logf: logf}
}

// stripTestFlags removes a testauth build's hidden leading flags from the
// arguments; in a production build there are none.
var stripTestFlags = func(args []string) []string { return args }

// daemonExtraArgs are given to a roverd the wrapper auto-starts, before
// "daemon" (a testauth build passes its flags on).
var daemonExtraArgs = func() []string { return nil }

// cliAuthTimeout bounds the dialog the CLI shows (`rover policy apply`).
const cliAuthTimeout = 150 * time.Second

// errNotAuthenticated refuses a change the human did not confirm.
var errNotAuthenticated = errors.New("refused: OS authentication did not succeed")

// authenticateCLI shows the dialog from the CLI and returns the method to
// record ("osauth:<method>").
func authenticateCLI(reason string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cliAuthTimeout)
	defer cancel()
	ok, method, err := newAuthenticator(errf).Authenticate(ctx, reason)
	if err != nil {
		return "", errors.Join(errNotAuthenticated, err)
	}
	if !ok {
		return "", errNotAuthenticated
	}
	return pin.MethodOSAuth + ":" + method, nil
}
