//go:build !amd64 && !arm64

package detect

import "encoding/binary"

// load8 returns t[i:i+8] as a little-endian uint64 (see load_fast.go).
func load8(t []byte, i int) uint64 {
	return binary.LittleEndian.Uint64(t[i : i+8])
}
