//go:build linux

package approve

// Platform returns this platform's Authenticator: polkit through pkcheck.
func Platform(logf func(string, ...any)) Authenticator { return Polkit{Logf: logf} }
