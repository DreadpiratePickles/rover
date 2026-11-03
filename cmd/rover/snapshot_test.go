package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Review M9 MEDIUM-4: a normalizers file outside the config directory is
// read exactly once per load; the hash and the loaded config come from
// those same bytes, so swapping the file between two reads is impossible.
func TestExternalNormalizersAreReadOnce(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	if out, err := run(dir, "policy", "init"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ext := filepath.Join(dir, "elsewhere", "normalizers.yaml")
	writeFile(t, ext, "servers:\n  files:\n    read_file: {path: path}\n")
	f, err := os.OpenFile(filepath.Join(dir, "config", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("normalizers: " + ext + "\n")
	_ = f.Close()
	reads := 0
	old := snapshotRead
	snapshotRead = func(p string, limit int) ([]byte, error) {
		b, rerr := old(p, limit)
		if p == ext {
			reads++
			// The attacker swaps the file right after Rover read it.
			_ = os.WriteFile(ext, []byte("servers: {}\n"), 0o600)
		}
		return b, rerr
	}
	defer func() { snapshotRead = old }()

	// Act
	_, cfg, _, hash, err := loadAll(dirsOf(dir))

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("the external normalizers file was read %d times, want 1", reads)
	}
	if len(cfg.Normalizers.Servers["files"]["read_file"]) == 0 {
		t.Fatal("the config must hold the bytes read the first time, not the swapped file")
	}
	snapshotRead = old
	after, err := loadedHash(dirsOf(dir))
	if err != nil || after == hash {
		t.Fatalf("the swapped file must hash differently: %v", err)
	}
}
