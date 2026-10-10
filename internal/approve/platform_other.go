//go:build !linux && !darwin

package approve

// Platform returns this platform's Authenticator: none exists, so it denies.
func Platform(func(string, ...any)) Authenticator {
	return Deny{Why: PlatformLimit()}
}

// PlatformLimit says why approvals can never succeed in this build, or "".
func PlatformLimit() string {
	return "Rover supports approvals on macOS and Linux only"
}
