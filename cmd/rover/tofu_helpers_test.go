package main

import (
	"path/filepath"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/state"
)

func dirsOf(dir string) paths.Dirs {
	return paths.Dirs{Config: filepath.Join(dir, "config"), State: filepath.Join(dir, "state"), Run: filepath.Join(dir, "run")}
}

// forgeApproval writes an approval straight into state.db, a minute in the
// future, as someone with file access but no dialog could.
func forgeApproval(dir, hash string) error {
	db, err := state.Open(filepath.Join(dir, "state", "state.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return approve.RecordPolicy(db, hash, "osauth:macos_local_authentication", time.Now().Add(time.Minute))
}
