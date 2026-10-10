package main

import (
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
