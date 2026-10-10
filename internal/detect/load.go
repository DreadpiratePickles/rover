package detect

import "encoding/binary"

// load8 returns t[i:i+8] as a little-endian uint64. The pass reads eight
// bytes at a time and takes them apart in registers. No unsafe: this parses
// attacker-controlled text, and speed does not buy an exception.
func load8(t []byte, i int) uint64 {
	return binary.LittleEndian.Uint64(t[i : i+8])
}
