package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// The approved-policy check (M9) needs the hash of exactly the bytes roverd
// loads. Reading the files twice (once to hash, once to load) would let an
// agent swap a file in between, so the config directory is first copied
// into a private snapshot under run/, and both the hash and the load read
// the snapshot.

// maxSnapshotFile bounds one copied file (the policy limit is the largest).
const maxSnapshotFile = policy.MaxPolicyBytes

// snapshotConfig copies every top-level regular file of dirs.Config into a
// fresh 0700 directory under dirs.Run, after checking each is owner-only
// (as loadConfig does for the originals). It returns dirs with Config
// pointing at the snapshot, and a cleanup function.
func snapshotConfig(dirs paths.Dirs) (paths.Dirs, func(), error) {
	snap, err := os.MkdirTemp(dirs.Run, "policy-load-")
	if err != nil {
		return dirs, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(snap) }
	entries, err := os.ReadDir(dirs.Config)
	if err != nil {
		cleanup()
		return dirs, func() {}, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue // templates/, sockets, symlinks: not part of what roverd loads
		}
		src := filepath.Join(dirs.Config, e.Name())
		err := copyPrivate(src, filepath.Join(snap, e.Name()))
		if err != nil && bundleFiles[e.Name()] {
			cleanup()
			return dirs, func() {}, err
		}
		// Another file (a normalizers file, notes, a proposal) is copied
		// with its own permission bits even when they are too open, so
		// loading the snapshot refuses it exactly as it would the original
		// if config.yaml names it; one too big or unreadable is left out.
		if err != nil {
			copyAsIs(src, filepath.Join(snap, e.Name()))
		}
	}
	out := dirs
	out.Config = snap
	return out, cleanup, nil
}

// bundleFiles must copy, or the snapshot fails.
var bundleFiles = map[string]bool{policyFile: true, policyYAMLFile: true, config.FileName: true, schemaFile: true}

func copyPrivate(src, dst string) error {
	if err := paths.CheckPrivate(src, 0o600); err != nil {
		return err
	}
	b, err := readCapped(src, maxSnapshotFile)
	if err != nil {
		return err
	}
	return writeNew(dst, b)
}

// copyAsIs copies src keeping its permission bits; failures leave it out.
func copyAsIs(src, dst string) {
	fi, err := os.Lstat(src)
	if err != nil {
		return
	}
	b, err := readCapped(src, maxSnapshotFile)
	if err != nil || writeNew(dst, b) != nil {
		return
	}
	_ = os.Chmod(dst, fi.Mode().Perm())
}

// bundleHash is the approved-policy hash of the bundle in configDir: the
// policy file roverd would pick, config.yaml, the schema and the
// normalizers file config.yaml names (when it parses).
func bundleHash(configDir string) (string, error) {
	file, _, err := pickPolicyFile(configDir)
	if err != nil {
		return "", err
	}
	parts := []approve.PolicyPart{}
	add := func(name, path string) error {
		b, err := readCapped(path, maxSnapshotFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			parts = append(parts, approve.PolicyPart{Name: name})
		case err != nil:
			return err
		default:
			parts = append(parts, approve.PolicyPart{Name: name, Data: b, Present: true})
		}
		return nil
	}
	for _, p := range [][2]string{{filepath.Base(file), file}, {config.FileName, filepath.Join(configDir, config.FileName)}, {schemaFile, filepath.Join(configDir, schemaFile)}} {
		if err := add(p[0], p[1]); err != nil {
			return "", err
		}
	}
	norm := ""
	if cfg, err := config.Load(configDir); err == nil {
		norm = cfg.NormalizersFile
	}
	if norm != "" {
		if err := add("normalizers", norm); err != nil {
			return "", err
		}
	}
	return approve.PolicyHash(parts), nil
}

// loadAll loads config.yaml and the policy for roverd from a snapshot of
// the config directory (see above): policy.cedar when it exists, else
// policy.yaml compiled at load (pickPolicyFile). The config, the chosen
// policy file, the schema and the normalizers file must be owner-only. It
// returns the bundle hash of what it loaded. On any error the caller runs
// (or keeps running) without this pair. note says which policy file was
// used.
func loadAll(dirs paths.Dirs) (pol daemon.Policy, cfg config.Config, note, hash string, err error) {
	snap, cleanup, err := snapshotConfig(dirs)
	defer cleanup()
	if err != nil {
		return nil, config.Config{}, "", "", err
	}
	unsnap := func(err error) error {
		if err == nil {
			return nil
		}
		return errors.New(strings.ReplaceAll(err.Error(), snap.Config, dirs.Config))
	}
	pol, cfg, note, err = loadSnapshot(snap)
	if err != nil {
		return nil, cfg, note, "", unsnap(err)
	}
	if hash, err = bundleHash(snap.Config); err != nil {
		return nil, cfg, note, "", unsnap(err)
	}
	return pol, cfg, note, hash, nil
}

// loadedHash is the bundle hash of the files on disk, whether or not they
// load (doctor reports a tampered or broken bundle either way).
func loadedHash(dirs paths.Dirs) (string, error) {
	snap, cleanup, err := snapshotConfig(dirs)
	defer cleanup()
	if err != nil {
		return "", err
	}
	h, err := bundleHash(snap.Config)
	if err != nil {
		return "", errors.New(strings.ReplaceAll(err.Error(), snap.Config, dirs.Config))
	}
	return h, nil
}
