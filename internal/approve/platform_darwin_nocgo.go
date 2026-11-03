//go:build darwin && !cgo

package approve

// Platform returns this platform's Authenticator. LocalAuthentication needs
// cgo; a binary built with CGO_ENABLED=0 cannot show the dialog, so it
// denies every approval rather than pretend.
func Platform(func(string, ...any)) Authenticator {
	return Deny{Why: PlatformLimit()}
}

// PlatformLimit says why approvals can never succeed in this build, or "".
func PlatformLimit() string {
	return "this rover was built without cgo, so it cannot call LocalAuthentication; rebuild with CGO_ENABLED=1"
}
