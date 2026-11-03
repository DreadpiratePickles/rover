package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample(i int) Entry {
	return Entry{Time: time.Unix(int64(i), 0).UTC(), Session: "s", Dir: "c2s", Kind: "request", Method: "ping", ID: json.RawMessage(`1`), Bytes: 10}
}

func TestChainVerifies(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	for i := 0; i < 5; i++ {
		if err := l.Write(sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	res := Verify(bytes.NewReader(buf.Bytes()))
	if res.Err != nil || res.Entries != 5 || res.LastHash != l.LastHash() {
		t.Fatalf("verify: %+v", res)
	}
}

// Acceptance (M1): editing one byte makes --verify fail at that line.
func TestOneByteEditIsDetectedAtItsLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	for i := 0; i < 5; i++ {
		_ = l.Write(sample(i))
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	// Flip one byte inside the method of line 3 ("ping" -> "pong").
	lines[2] = bytes.Replace(lines[2], []byte(`"method":"ping"`), []byte(`"method":"pong"`), 1)
	tampered := bytes.Join(lines, []byte("\n"))
	res := Verify(bytes.NewReader(tampered))
	if !errors.Is(res.Err, ErrChainBroken) || res.Line != 3 {
		t.Fatalf("want break at line 3, got %+v", res)
	}
}

func TestDroppedLineIsDetected(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	for i := 0; i < 4; i++ {
		_ = l.Write(sample(i))
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	lines = append(lines[:1], lines[2:]...) // drop line 2
	res := Verify(bytes.NewReader(bytes.Join(lines, []byte("\n"))))
	if !errors.Is(res.Err, ErrChainBroken) || res.Line != 2 {
		t.Fatalf("want break at line 2, got %+v", res)
	}
}

func TestWhitespaceEditIsDetected(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	_ = l.Write(sample(1))
	edited := bytes.Replace(buf.Bytes(), []byte(`"kind":`), []byte(`"kind": `), 1)
	res := Verify(bytes.NewReader(edited))
	if !errors.Is(res.Err, ErrChainBroken) || res.Line != 1 {
		t.Fatalf("want break at line 1, got %+v", res)
	}
}

func TestOpenResumesChainAndRefusesCorruptTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Write(sample(1))
	first := l.LastHash()
	_ = l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if l2.LastHash() != first {
		t.Fatalf("chain not resumed: %q vs %q", l2.LastHash(), first)
	}
	_ = l2.Write(sample(2))
	_ = l2.Close()

	f, _ := os.Open(path) //nolint:gosec // G304: the test's own temp file
	res := Verify(f)
	_ = f.Close()
	if res.Err != nil || res.Entries != 2 {
		t.Fatalf("after reopen: %+v", res)
	}

	data, _ := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	data = bytes.Replace(data, []byte(`"session":"s"`), []byte(`"session":"x"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open must refuse to append to a broken chain")
	}
}

func TestFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %o, want 600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(path))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %o, want 700", di.Mode().Perm())
	}
}

func TestRotationKeepsChainAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.RotateBytes = 400 // a few entries per file
	for i := 0; i < 10; i++ {
		if err := l.Write(sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	matches, _ := filepath.Glob(path + ".*")
	if len(matches) == 0 {
		t.Fatal("expected at least one rotated file")
	}
	// The current file's first entry must link to the previous file's last hash.
	prevFile := matches[len(matches)-1]
	pf, _ := os.Open(prevFile) //nolint:gosec // G304: the test's own temp file
	prev := Verify(pf)
	_ = pf.Close()
	cf, _ := os.Open(path) //nolint:gosec // G304: the test's own temp file
	cur := Verify(cf)
	_ = cf.Close()
	if prev.Err != nil || cur.Err != nil {
		t.Fatalf("verify: prev %+v cur %+v", prev, cur)
	}
	if cur.FirstPrev != prev.LastHash {
		t.Fatalf("current file does not continue previous: %q vs %q", cur.FirstPrev, prev.LastHash)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	res := Verify(strings.NewReader(""))
	if res.Err != nil || res.Entries != 0 {
		t.Fatalf("%+v", res)
	}
}
