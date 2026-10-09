//go:build race

package detect

// raceBuild: the race detector makes every memory access ~10x slower.
const raceBuild = true
