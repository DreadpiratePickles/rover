//go:build !unix

package paths

import (
	"errors"
	"os"
)

// Rover only runs on Unix-like systems; elsewhere ownership cannot be
// checked, so CheckPerms fails closed.
func ownerUID(os.FileInfo) (int, error) {
	return 0, errors.New("paths: cannot check directory ownership on this OS")
}
