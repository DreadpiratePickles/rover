package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return fixedNow }

func entry(i int) Entry {
	return Entry{
		Session: "s1",
		Server:  "echo",
		Dir:     "c2s",
		Kind:    "request",
		Method:  "tools/call",
		ID:      json.RawMessage(`` + string(rune('0'+i%10))),
		Bytes:   42 + i,
		Body:    json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello there"}}}`),
	}
}

// writeLog writes n entries to a buffer-backed logger and returns the bytes.
func writeLog(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	l := New(&buf)
	l.Now = clock
	for i := range n {
		if err := l.Write(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func lines(b []byte) [][]byte {
	return bytes.SplitAfter(b, []byte("\n"))[:bytes.Count(b, []byte("\n"))]
}

func wantBreak(t *testing.T, err error, line int) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("want VerifyError at line %d, got %v", line, err)
	}
	if ve.Line != line {
		t.Fatalf("break reported at line %d (%s), want line %d", ve.Line, ve.Reason, line)
	}
}

func TestChainVerifies(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Now = clock
	for i := range 3 {
		if err := l.Write(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	n, last, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil || n != 3 || last != l.LastHash() {
		t.Fatalf("Verify = %d, %q, %v; want 3, %q, nil", n, last, err, l.LastHash())
	}
	var first Entry
	if err := json.Unmarshal(lines(buf.Bytes())[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Prev != "" || len(first.Hash) != 64 || !first.Time.Equal(fixedNow) || first.Server != "echo" {
		t.Fatalf("first entry = %+v", first)
	}
}

// The hash covers exactly the json.Marshal bytes of the entry without its
// hash, and the line is those bytes with the hash spliced in before the '}'.
func TestLineFormat(t *testing.T) {
	ls := lines(writeLog(t, 2))
	var e Entry
	if err := json.Unmarshal(ls[1], &e); err != nil {
		t.Fatal(err)
	}
	hash := e.Hash
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatal("hash is not SHA-256 of the entry's JSON without the hash")
	}
	want := string(b[:len(b)-1]) + `,"hash":"` + hash + `"}` + "\n"
	if string(ls[1]) != want {
		t.Fatalf("line =\n%s\nwant\n%s", ls[1], want)
	}
	if !strings.Contains(string(ls[1]), `"prev":"`) || strings.Contains(string(ls[0]), `"prev":"`+hash) {
		t.Fatal("prev field missing or wrong")
	}
}

// Acceptance (M1): editing one byte of the log makes verification fail at
// that line.
func TestFlipOneByteDetectedAtThatLine(t *testing.T) {
	orig := writeLog(t, 5)
	for n := 1; n <= 5; n++ {
		ls := lines(bytes.Clone(orig))
		mid := len(ls[n-1]) / 2
		ls[n-1][mid] ^= 0x01
		_, _, err := Verify(bytes.NewReader(bytes.Join(ls, nil)))
		wantBreak(t, err, n)
	}
}

// Changing a value to something that is still valid JSON is also caught.
func TestEditedValueDetected(t *testing.T) {
	log := bytes.Replace(writeLog(t, 5), []byte(`"bytes":44`), []byte(`"bytes":45`), 1)
	_, _, err := Verify(bytes.NewReader(log))
	wantBreak(t, err, 3)
}

func TestTruncatedLastLineDetected(t *testing.T) {
	log := writeLog(t, 5)
	for _, cut := range []int{1, 10, 100} { // 1 = only the trailing newline
		_, _, err := Verify(bytes.NewReader(log[:len(log)-cut]))
		wantBreak(t, err, 5)
	}
}

func TestDeletedMiddleLineDetected(t *testing.T) {
	ls := lines(writeLog(t, 5))
	without3 := bytes.Join(append(ls[:2:2], ls[3:]...), nil)
	_, _, err := Verify(bytes.NewReader(without3))
	wantBreak(t, err, 3) // the old line 4 is now line 3, and its prev points at the deleted entry
}

func TestSwappedLinesDetected(t *testing.T) {
	ls := lines(writeLog(t, 5))
	ls[1], ls[2] = ls[2], ls[1]
	_, _, err := Verify(bytes.NewReader(bytes.Join(ls, nil)))
	wantBreak(t, err, 2)
}

func TestGarbageLines(t *testing.T) {
	for name, in := range map[string]string{
		"blank line":   "\n",
		"not json":     "hello\n",
		"empty object": "{}\n",
		"no prev":      fakeLine(`{"a":1}`),
		"prev number":  fakeLine(`{"prev":1}`),
	} {
		_, _, err := Verify(strings.NewReader(in))
		var ve *VerifyError
		if !errors.As(err, &ve) || ve.Line != 1 {
			t.Errorf("%s: err = %v, want a break at line 1", name, err)
		}
	}
}

// fakeLine makes a line with a correct hash for arbitrary object bytes b.
func fakeLine(b string) string {
	sum := sha256.Sum256([]byte(b))
	return b[:len(b)-1] + `,"hash":"` + hex.EncodeToString(sum[:]) + `"}` + "\n"
}

func TestVerifyEmpty(t *testing.T) {
	n, last, err := Verify(strings.NewReader(""))
	if n != 0 || last != "" || err != nil {
		t.Fatalf("Verify(empty) = %d %q %v", n, last, err)
	}
}

func TestVerifyLineTooLong(t *testing.T) {
	big := strings.Repeat("x", MaxLineBytes+10)
	_, _, err := Verify(strings.NewReader(big))
	wantBreak(t, err, 1)
}

type flakyWriter struct{ calls int }

func (w *flakyWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(p) / 2, errors.New("disk full")
	}
	return len(p), nil
}

// After a failed (possibly partial) write the logger must not append more.
func TestWriteFailureIsSticky(t *testing.T) {
	w := &flakyWriter{}
	l := New(w)
	if err := l.Write(entry(0)); err == nil {
		t.Fatal("first write should fail")
	}
	if err := l.Write(entry(1)); err == nil || w.calls != 1 {
		t.Fatalf("second write: err=%v calls=%d; want error and no write", err, w.calls)
	}
}

func TestInvalidBodyRejectedWithoutBreakingChain(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	e := entry(0)
	e.Body = json.RawMessage(`{not json`)
	if err := l.Write(e); err == nil {
		t.Fatal("invalid body accepted")
	}
	if err := l.Write(entry(1)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := Verify(&buf); err != nil || n != 1 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func openLog(t *testing.T, dir string) *Logger {
	t.Helper()
	l, err := Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	l.Now = clock
	return l
}

func closeLog(t *testing.T, l *Logger) {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRecoversLastHash(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir)
	for i := range 2 {
		if err := l.Write(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	h := l.LastHash()
	closeLog(t, l)
	if err := l.Write(entry(9)); err == nil {
		t.Fatal("write after Close succeeded")
	}

	l = openLog(t, dir)
	if l.LastHash() != h {
		t.Fatalf("recovered hash %q, want %q", l.LastHash(), h)
	}
	if err := l.Write(entry(2)); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)

	n, last, err := VerifyFiles(dir)
	if err != nil || n != 3 || last == h {
		t.Fatalf("VerifyFiles = %d, %q, %v", n, last, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", fi.Mode().Perm())
	}
}

// Fail closed: don't append to a chain whose end is damaged.
func TestOpenRefusesDamagedLastLine(t *testing.T) {
	for name, tail := range map[string]string{
		"garbage line":  "garbage\n",
		"no newline":    `{"partial":`,
		"edited object": fakeLine(`{"prev":"x"}`)[:20] + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			l := openLog(t, dir)
			if err := l.Write(entry(0)); err != nil {
				t.Fatal(err)
			}
			closeLog(t, l)
			path := filepath.Join(dir, "audit.jsonl")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // G304: path is inside t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tail); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "--verify") {
				t.Fatalf("Open accepted a damaged log, err=%v", err)
			}
		})
	}
}

func TestOpenRefusesLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the test deliberately loosens the file
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("0644 audit log accepted")
	}
}

// Rotation at a 1 KiB threshold: the first entry of each new file links to
// the last entry of the previous one, and VerifyFiles follows the chain.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir)
	l.MaxBytes = 1024
	var hashes []string
	for i := range 6 { // each line is ~400 bytes: rotation after the 3rd and 6th
		if err := l.Write(entry(i)); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, l.LastHash())
	}
	closeLog(t, l)

	first := filepath.Join(dir, "audit-20261009T120000Z.jsonl")
	second := filepath.Join(dir, "audit-20261009T120000Z-1.jsonl") // same second: no overwrite
	for _, p := range []string{first, second} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("rotated file missing: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", p, fi.Mode().Perm())
		}
	}
	cur, err := os.ReadFile(filepath.Join(dir, "audit.jsonl")) //nolint:gosec // G304: path is inside t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 0 {
		t.Fatalf("current log should be empty right after rotation, has %d bytes", len(cur))
	}
	b, err := os.ReadFile(second) //nolint:gosec // G304: path is inside t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var e Entry
	if err = json.Unmarshal(lines(b)[0], &e); err != nil {
		t.Fatal(err)
	}
	if e.Prev != hashes[2] {
		t.Fatalf("second file's first prev = %q, want last hash of the first file %q", e.Prev, hashes[2])
	}

	// Restarting after a rotation continues from the newest rotated file.
	l = openLog(t, dir)
	if l.LastHash() != hashes[5] {
		t.Fatalf("reopened with %q, want %q", l.LastHash(), hashes[5])
	}
	if err = l.Write(entry(6)); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)

	n, last, err := VerifyFiles(dir)
	if err != nil || n != 7 {
		t.Fatalf("VerifyFiles = %d, %v; want 7 entries", n, err)
	}
	if last == hashes[5] || last == "" {
		t.Fatalf("last = %q", last)
	}

	// Deleting a whole old file is a break too.
	if err = os.Remove(first); err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyFiles(dir)
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.File != second || ve.Line != 1 {
		t.Fatalf("after deleting the oldest file: %v", err)
	}
}

func TestRotationUsesClock(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir)
	l.MaxBytes = 1
	l.Now = func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)) }
	if err := l.Write(entry(0)); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)
	if _, err := os.Stat(filepath.Join(dir, "audit-20300102T020405Z.jsonl")); err != nil {
		t.Fatalf("rotated name not from the injected clock in UTC: %v", err)
	}
}

func TestVerifyFilesNoLog(t *testing.T) {
	if _, _, err := VerifyFiles(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestVerifyFilesRefusesUnknownRotatedName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit-backup.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFiles(dir); err == nil {
		t.Fatal("unknown audit-*.jsonl file accepted")
	}
}

func TestRotatedOrdering(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"audit-20261009T120000Z.jsonl", true},
		{"audit-20261009T120000Z-2.jsonl", true},
		{"audit-20261009T120000Z-0.jsonl", false},
		{"audit-20261009T120000Z-02.jsonl", false},
		{"audit-2026-10-09.jsonl", false},
		{"audit-20261309T120000Z.jsonl", false},
	} {
		if _, ok := parseRotated("audit.jsonl", tc.name); ok != tc.ok {
			t.Errorf("parseRotated(%q) ok=%v, want %v", tc.name, ok, tc.ok)
		}
	}
}

// FuzzVerifyLine: Verify reads attacker-controllable files, so it must never
// panic, and whatever checkLine accepts must really carry a matching hash.
func FuzzVerifyLine(f *testing.F) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Now = clock
	_ = l.Write(entry(0))
	_ = l.Write(entry(1))
	f.Add(buf.Bytes())
	f.Add(lines(buf.Bytes())[0])
	f.Add([]byte("{}\n"))
	f.Add([]byte(fakeLine(`{"prev":""}`)))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = Verify(bytes.NewReader(b))
		line := bytes.TrimSuffix(b, []byte("\n"))
		if _, h, reason := checkLine(line); reason == "" {
			body := append(bytes.Clone(line[:len(line)-suffixLen]), '}')
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != h || !json.Valid(line) {
				t.Fatalf("checkLine accepted a line whose hash does not match: %q", line)
			}
		}
		_, _ = lastHashOf(bytes.NewReader(b), int64(len(b)))
	})
}
