//go:build !linux && !darwin

package approve

// Platform returns this platform's Authenticator: none exists, so it denies.
func Platform(func(string, ...any)) Authenticator {
	return Deny{Why: "Rover supports approvals on macOS and Linux only"}
}
