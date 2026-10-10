//go:build !unix

package daemon

// pidAlive cannot check on this platform: assume alive, so a session
// lingers until LingerMax (the conservative side).
func pidAlive(int) bool { return true }
