package clients

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/DreadpiratePickles/rover/internal/paths"
)

// KeepBackups is how many backups are kept per config file.
const KeepBackups = 5

// Errors from Restore and ApplyPlan.
var (
	// ErrChangedSinceInstall: the file is not what rover last wrote, so
	// putting the backup back would throw away someone's later changes.
	ErrChangedSinceInstall = errors.New("the file changed since rover wrote it")
	// ErrBackupCorrupt: the backup's bytes do not match the checksum taken
	// when it was made; restoring it could install something nobody wrote.
	ErrBackupCorrupt = errors.New("backup does not match its recorded sha256")
	// ErrNoBackup: rover never wrote this file (or every backup is used).
	ErrNoBackup = errors.New("no backup to restore")
	// ErrChangedSincePlan: the file changed between Plan and Apply.
	ErrChangedSincePlan = errors.New("the file changed since the plan was made; run the command again")
)

// manifest records the backups of one config file, oldest first.
type manifest struct {
	Adapter string        `json:"adapter"`
	Path    string        `json:"path"`
	Scope   string        `json:"scope"`
	Entries []backupEntry `json:"entries"`
}

type backupEntry struct {
	Time time.Time `json:"time"`
	// Backup is the file name of the saved original ("" when Created).
	Backup       string `json:"backup,omitempty"`
	BackupSHA256 string `json:"backup_sha256,omitempty"`
	// WrittenSHA256 is the sha256 of what rover wrote over it.
	WrittenSHA256 string `json:"written_sha256"`
	// Created: the file did not exist; restoring removes it.
	Created  bool `json:"created,omitempty"`
	Restored bool `json:"restored,omitempty"`
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// backupDir is <BackupDir>/<adapter>/<sha256 of the path>.
func backupDir(env Env, cf ConfigFile) string {
	return filepath.Join(env.BackupDir, cf.Adapter, sum([]byte(cf.Path)))
}

// ApplyPlan writes p: it checks the file still holds p.Orig, saves p.Orig
// as a backup (0600, beside a manifest with its checksum), replaces the
// file atomically, then records the new checksum. Nothing is written for a
// plan without changes.
func ApplyPlan(env Env, p Plan) error {
	if !p.HasChanges() {
		return nil
	}
	if env.BackupDir == "" {
		return errors.New("no backup directory configured")
	}
	target, mode, err := resolve(p.File.Path, p.Created)
	if err != nil {
		return err
	}
	cur, err := readCapped(target)
	switch {
	case p.Created && errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	case p.Created || !bytes.Equal(cur, p.Orig):
		return fmt.Errorf("%s: %w", p.File.Path, ErrChangedSincePlan)
	}
	dir := backupDir(env, p.File)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err = paths.CheckPrivate(dir, 0o700); err != nil {
		return err
	}
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	m.Adapter, m.Path, m.Scope = p.File.Adapter, p.File.Path, p.File.Scope
	e := backupEntry{Time: env.now().UTC(), WrittenSHA256: sum(p.New), Created: p.Created}
	if !p.Created {
		e.Backup = strconv.FormatInt(e.Time.UnixNano(), 10) + ".json"
		if err := writeExclusive(filepath.Join(dir, e.Backup), p.Orig); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		e.BackupSHA256 = sum(p.Orig)
	} else if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	if err := WriteAtomic(target, p.New, mode); err != nil {
		return err
	}
	m.Entries = append(m.Entries, e)
	prune(dir, &m)
	return writeManifest(dir, m)
}

// resolve follows a symlinked config to the real file (dotfile managers
// link them), so the rename replaces the file, not the link. It returns
// the mode to keep; a file rover creates is 0600.
func resolve(path string, created bool) (string, os.FileMode, error) {
	target, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) && created {
		return path, 0o600, nil
	}
	if err != nil {
		return "", 0, err
	}
	fi, err := os.Stat(target)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%s is not a regular file", path)
	}
	return target, fi.Mode().Perm(), nil
}

// Restore puts back the newest backup of cf, if the file still holds what
// rover wrote and the backup still matches its checksum. Anything else is
// refused with the reason: restoring over later edits, or from a backup
// someone altered, would be worse than doing nothing.
func Restore(env Env, cf ConfigFile) error {
	dir := backupDir(env, cf)
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	i := latest(m)
	if i < 0 {
		return fmt.Errorf("%s: %w", cf.Path, ErrNoBackup)
	}
	e := m.Entries[i]
	target, mode, err := resolve(cf.Path, false)
	if err != nil {
		return err
	}
	cur, err := readCapped(target)
	if err != nil {
		return err
	}
	if sum(cur) != e.WrittenSHA256 {
		return fmt.Errorf("%s: %w (sha256 %.12s, rover wrote %.12s); restoring the backup would discard those changes", cf.Path, ErrChangedSinceInstall, sum(cur), e.WrittenSHA256)
	}
	if e.Created {
		if err := os.Remove(target); err != nil {
			return err
		}
	} else {
		bpath := filepath.Join(dir, filepath.Base(e.Backup))
		b, err := readCapped(bpath)
		if err != nil {
			return fmt.Errorf("backup %s: %w", bpath, err)
		}
		if sum(b) != e.BackupSHA256 {
			return fmt.Errorf("%s: %w: %s has sha256 %.12s, recorded %.12s; refusing to restore it (inspect it, or edit the config by hand)",
				cf.Path, ErrBackupCorrupt, bpath, sum(b), e.BackupSHA256)
		}
		if err := WriteAtomic(target, b, mode); err != nil {
			return err
		}
	}
	m.Entries[i].Restored = true
	return writeManifest(dir, m)
}

// RestorePreview returns the diff Restore would apply, or the reason it
// would refuse (the same checks, nothing written).
func RestorePreview(env Env, cf ConfigFile) (string, error) {
	dir := backupDir(env, cf)
	m, err := readManifest(dir)
	if err != nil {
		return "", err
	}
	i := latest(m)
	if i < 0 {
		return "", fmt.Errorf("%s: %w", cf.Path, ErrNoBackup)
	}
	e := m.Entries[i]
	cur, err := readCapped(cf.Path)
	if err != nil {
		return "", err
	}
	if sum(cur) != e.WrittenSHA256 {
		return "", fmt.Errorf("%s: %w", cf.Path, ErrChangedSinceInstall)
	}
	if e.Created {
		return fmt.Sprintf("--- %s\n(rover created this file; restoring removes it)\n", cf.Path), nil
	}
	b, err := readCapped(filepath.Join(dir, filepath.Base(e.Backup)))
	if err != nil {
		return "", err
	}
	if sum(b) != e.BackupSHA256 {
		return "", fmt.Errorf("%s: %w", cf.Path, ErrBackupCorrupt)
	}
	return wholeDiff(cf.Path, cur, b), nil
}

// HasBackup reports whether cf has a backup that was not restored yet.
func HasBackup(env Env, cf ConfigFile) bool {
	m, err := readManifest(backupDir(env, cf))
	return err == nil && latest(m) >= 0
}

func latest(m manifest) int {
	for i := len(m.Entries) - 1; i >= 0; i-- {
		if !m.Entries[i].Restored {
			return i
		}
	}
	return -1
}

// InstalledFiles lists every config file rover has written (from the
// manifests). roverd watches these for tampering.
func InstalledFiles(backupRoot string) ([]ConfigFile, error) {
	ms, err := filepath.Glob(filepath.Join(backupRoot, "*", "*", "manifest.json"))
	if err != nil {
		return nil, err
	}
	var out []ConfigFile
	for _, p := range ms {
		m, err := readManifest(filepath.Dir(p))
		if err != nil {
			return nil, err
		}
		if _, ok := specs[m.Adapter]; ok && m.Path != "" {
			out = append(out, ConfigFile{Adapter: m.Adapter, Path: m.Path, Scope: m.Scope})
		}
	}
	return out, nil
}

// prune keeps the newest KeepBackups entries and deletes older backups.
func prune(dir string, m *manifest) {
	sort.SliceStable(m.Entries, func(i, j int) bool { return m.Entries[i].Time.Before(m.Entries[j].Time) })
	for len(m.Entries) > KeepBackups {
		if b := m.Entries[0].Backup; b != "" {
			_ = os.Remove(filepath.Join(dir, filepath.Base(b)))
		}
		m.Entries = m.Entries[1:]
	}
}

func readManifest(dir string) (manifest, error) {
	b, err := readCapped(filepath.Join(dir, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return manifest{}, nil
	}
	if err != nil {
		return manifest{}, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return manifest{}, fmt.Errorf("backup manifest %s: %w", dir, err)
	}
	return m, nil
}

func writeManifest(dir string, m manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o600)
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a path under rover's own state directory
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteAtomic replaces path with data: a temporary file in the same
// directory (so the rename stays on one file system), fsync, rename over
// path, then fsync the directory. A crash leaves the old file or the new
// one, never half of each.
func WriteAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".rover-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		if err = f.Chmod(mode); err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil { //nolint:gosec // G304: the directory of the file just written
		_ = d.Sync() // best effort: some file systems refuse fsync on directories
		_ = d.Close()
	}
	return nil
}
