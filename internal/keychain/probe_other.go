//go:build !linux

package keychain

// available: macOS always has a login keychain; other platforms fail in
// go-keyring itself with ErrUnsupportedPlatform, which maps to ErrNoKeychain.
func available() error { return nil }

func noService(error) bool { return false }
