//go:build race

package dlp

// raceBuild: the race detector makes every memory access ~10x slower.
const raceBuild = true
