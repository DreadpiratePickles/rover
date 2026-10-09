//go:build unix

package paths

import (
	"os"
	"syscall"
)

// fileOwner returns the uid that owns a file, when the platform reports it.
func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
