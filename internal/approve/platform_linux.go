//go:build linux

package approve

// Platform returns this platform's Authenticator: polkit through pkcheck.
func Platform(logf func(string, ...any)) Authenticator { return Polkit{Logf: logf} }

// PlatformLimit says why approvals can never succeed in this build, or "".
func PlatformLimit() string { return "" }
