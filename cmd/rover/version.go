package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set by the release build (.goreleaser.yaml ldflags).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString is what `rover version` prints. A plain `go build` has no
// ldflags, so the commit then comes from the VCS stamp Go embeds.
func versionString() string {
	c, d, dirty := commit, date, false
	if info, ok := debug.ReadBuildInfo(); ok && c == "none" {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				c = s.Value
			case "vcs.time":
				d = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	if len(c) > 12 {
		c = c[:12]
	}
	if dirty {
		c += "-dirty"
	}
	return fmt.Sprintf("rover %s (commit %s, built %s, %s %s/%s)", version, c, d, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func runVersion([]string) int {
	fmt.Println(versionString())
	return 0
}
