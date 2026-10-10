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

func writeN(t *testing.T, l *Logger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Write(sample(i)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyChainDetectsRemovedHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	writeN(t, l, 3)
	_ = l.Close()
	data, _ := os.ReadFile(path) //nolint:gosec // G304: test's own file
	lines := bytes.SplitAfter(data, []byte("\n"))
	if err := os.WriteFile(path, bytes.Join(lines[1:], nil), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	files, _ := ChainFiles(path)
	res := VerifyChain(files, "")
	if !errors.Is(res.Err, ErrChainBroken) || !strings.Contains(res.Err.Error(), "head") {
		t.Fatalf("removed head not detected: %+v", res)
	}
}

func TestVerifyChainDetectsRemovedTailViaAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	anchor := filepath.Join(dir, "audit.anchor")
	l, _ := Open(path)
	l.AnchorPath = anchor
	writeN(t, l, 3)
	_ = l.Close()
	a, err := ReadAnchor(anchor)
	if err != nil || a != l.LastHash() {
		t.Fatalf("anchor %q err %v, want %q", a, err, l.LastHash())
	}
	files, _ := ChainFiles(path)
	if res := VerifyChain(files, a); res.Err != nil || res.Entries != 3 {
		t.Fatalf("intact log failed: %+v", res)
	}
	data, _ := os.ReadFile(path) //nolint:gosec // G304: test's own file
	lines := bytes.SplitAfter(data, []byte("\n"))
	if err := os.WriteFile(path, bytes.Join(lines[:2], nil), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	res := VerifyChain(files, a)
	if !errors.Is(res.Err, ErrChainBroken) || !strings.Contains(res.Err.Error(), "tail") {
		t.Fatalf("removed tail not detected: %+v", res)
	}
}

func TestVerifyChainAcrossRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, _ := Open(path)
	l.RotateBytes = 400
	writeN(t, l, 10)
	_ = l.Close()
	files, err := ChainFiles(path)
	if err != nil || len(files) < 2 || files[len(files)-1] != path {
		t.Fatalf("files %v err %v", files, err)
	}
	if res := VerifyChain(files, ""); res.Err != nil || res.Entries != 10 {
		t.Fatalf("rotated chain: %+v", res)
	}
	// Delete the oldest file: the next one now claims a predecessor that is gone.
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	files, _ = ChainFiles(path)
	if res := VerifyChain(files, ""); !errors.Is(res.Err, ErrChainBroken) {
		t.Fatalf("missing oldest file not detected: %+v", res)
	}
}

// A body full of '<' must not inflate the line: HTML escaping is off.
func TestBodiesAreNotHTMLEscaped(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	e := sample(1)
	e.Body = json.RawMessage(`{"x":"` + strings.Repeat("<", 1000) + `"}`)
	if err := l.Write(e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `\u003c`) {
		t.Fatal("body was HTML-escaped")
	}
	if buf.Len() > 1300 {
		t.Fatalf("line inflated to %d bytes", buf.Len())
	}
	if res := Verify(bytes.NewReader(buf.Bytes())); res.Err != nil {
		t.Fatalf("verify: %+v", res)
	}
}

func TestWriteRefusesOversizedEntry(t *testing.T) {
	l := New(&bytes.Buffer{})
	e := sample(1)
	e.Body = json.RawMessage(`{"x":"` + strings.Repeat("a", MaxLine) + `"}`)
	if err := l.Write(e); err == nil {
		t.Fatal("an entry larger than MaxLine must be refused, not written")
	}
}

func FuzzVerify(f *testing.F) {
	var buf bytes.Buffer
	l := New(&buf)
	_ = l.Write(Entry{Time: time.Unix(1, 0).UTC(), Session: "s", Dir: "c2s", Kind: "request", Method: "ping", Bytes: 1})
	f.Add(buf.Bytes())
	f.Add([]byte("{"))
	f.Add([]byte(""))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_ = Verify(bytes.NewReader(b))
	})
}
