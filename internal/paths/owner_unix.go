//go:build unix

package paths

import (
	"fmt"
	"os"
	"syscall"
)

func ownerUID(fi os.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read the owner of %s", fi.Name())
	}
	return int(st.Uid), nil
}
