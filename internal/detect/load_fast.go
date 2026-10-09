//go:build amd64 || arm64

package detect

import "unsafe"

// load8 returns t[i:i+8] as a little-endian uint64 with ONE memory read.
//
// Why unsafe: under the race detector (`make test` runs every test with
// -race) each Go-level memory access costs ~20 ns, so a byte-at-a-time pass
// over a 64 KB result costs ~1.5 ms before any rule runs, most of the 2 ms
// budget. One 8-byte read per 8 bytes keeps the scan within budget in race
// builds as well. amd64 and arm64 are little-endian and allow unaligned
// loads; other architectures use load_portable.go.
func load8(t []byte, i int) uint64 {
	_ = t[i+7]                               // bounds check: the read below stays inside t
	return *(*uint64)(unsafe.Pointer(&t[i])) //nolint:gosec // G103: bounds-checked 8-byte read inside t, see above
}
