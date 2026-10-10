package clients

import (
	"errors"
	"fmt"
	"strings"
)

// maxUnwrapRounds bounds the in-place unwrap loop of Uninstall. Each round
// removes one layer of wrapping from every server, so this is the deepest
// stack of `rover wrap -- rover wrap -- ...` it will peel.
const maxUnwrapRounds = 10

// Uninstall leaves cf with no rover-wrapped server, or fails saying why.
// It puts back the newest backup when the file is exactly what rover last
// wrote (byte-identical to before that install), then re-reads the file
// and unwraps in place whatever is still wrapped (an earlier install, a
// server added and wrapped later), repeating until nothing is. A backup
// that fails its checksum stops it before anything is written. steps says
// what was done, in order.
func Uninstall(env Env, cf ConfigFile) (steps []string, err error) {
	if HasBackup(env, cf) {
		switch err := Restore(env, cf); {
		case err == nil:
			steps = append(steps, "restored the newest backup")
		case errors.Is(err, ErrChangedSinceInstall):
			steps = append(steps, "the file changed since rover wrote it; kept it and unwrapped in place")
		default:
			return steps, err
		}
	}
	for round := 0; round < maxUnwrapRounds; round++ {
		doc, err := ReadConfig(cf)
		if err != nil {
			return steps, err
		}
		p, err := PlanUnwrap(doc)
		if err != nil {
			return steps, err
		}
		if !p.HasChanges() {
			if err := consumeBackups(env, cf); err != nil {
				return steps, err
			}
			return steps, nil
		}
		if err := ApplyPlan(env, p); err != nil {
			return steps, err
		}
		steps = append(steps, "unwrapped in place: "+strings.Join(p.Changed, ", "))
	}
	return steps, fmt.Errorf("%s: still wrapped after %d rounds of unwrapping; edit it by hand", cf.Path, maxUnwrapRounds)
}

// consumeBackups marks every backup of cf as used, so a later uninstall
// never restores a wrapped file over a clean one.
func consumeBackups(env Env, cf ConfigFile) error {
	dir := backupDir(env, cf)
	m, err := readManifest(dir)
	if err != nil || len(m.Entries) == 0 {
		return err
	}
	for i := range m.Entries {
		m.Entries[i].Restored = true
	}
	return writeManifest(dir, m)
}
