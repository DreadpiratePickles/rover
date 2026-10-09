package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The on-disk line format (plan §4.6, M1 spec):
//
//  1. Marshal the entry with Hash == "" (omitempty drops the field) -> B.
//     B is a JSON object, so it ends with '}'.
//  2. H = hex(SHA-256(B)).
//  3. Write B[:len(B)-1] + `,"hash":"` + H + `"}` + "\n".
//
// So every line ends with a fixed-length suffix, and verifying needs no
// re-marshalling: cut the suffix off, put the '}' back, and you have B again,
// byte for byte.
//
// LESSON: never verify by decoding and re-encoding. Two encoders (or two
// versions of one) can produce different bytes for the same data, and then
// the hash "fails" for an untouched entry, or worse, an edit that survives a
// round-trip goes unnoticed. Hash exact bytes.
const (
	hashKey   = `,"hash":"`
	hashHex   = sha256.Size * 2
	suffixLen = len(hashKey) + hashHex + len(`"}`)

	// MaxLineBytes bounds one log line when reading. Entries carry at most one
	// 16 MiB message body plus metadata; anything longer is not ours.
	MaxLineBytes = 32 << 20

	rotateLayout = "20060102T150405Z"
)

// encodeLine returns the line to write for e (with its trailing newline) and
// e's hash. e.Hash is ignored.
func encodeLine(e Entry) (line []byte, hash string, err error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	hash = hex.EncodeToString(sum[:])
	line = make([]byte, 0, len(b)-1+suffixLen+1)
	line = append(line, b[:len(b)-1]...)
	line = append(line, hashKey...)
	line = append(line, hash...)
	line = append(line, `"}`+"\n"...)
	return line, hash, nil
}

// checkLine verifies one line (without its newline) on its own: the hash
// suffix is present and matches the bytes before it, and the line is a JSON
// object with a string "prev". It returns prev and the line's hash, or a
// non-empty reason.
//
// The suffix is found at a fixed offset from the end. Because the line must
// be valid JSON and ends with `,"hash":"<64 hex>"}`, those bytes are real JSON
// tokens closing the top-level object (a '"' inside a string would have to be
// escaped as \"), so "hash" is a top-level member, not text inside a value.
func checkLine(l []byte) (prev, hash, reason string) {
	if len(l) < suffixLen+1 {
		return "", "", "line too short to carry a hash"
	}
	cut := len(l) - suffixLen
	suf := l[cut:]
	if !bytes.HasPrefix(suf, []byte(hashKey)) || !bytes.HasSuffix(suf, []byte(`"}`)) {
		return "", "", `line does not end with ,"hash":"<sha256>"}`
	}
	hash = string(suf[len(hashKey) : len(hashKey)+hashHex])
	h := sha256.New()
	h.Write(l[:cut])     // hash.Hash.Write never returns an error
	h.Write([]byte{'}'}) // B = line without the suffix, plus the closing brace
	if hex.EncodeToString(h.Sum(nil)) != hash {
		return "", "", "hash mismatch: the entry was modified"
	}
	var p struct {
		Prev *string `json:"prev"`
	}
	if err := json.Unmarshal(l, &p); err != nil {
		return "", "", "not a valid JSON object: " + err.Error()
	}
	if p.Prev == nil {
		return "", "", `missing "prev"`
	}
	return *p.Prev, hash, ""
}

// VerifyError reports the first break in the chain.
type VerifyError struct {
	File   string // set by VerifyFiles; empty for Verify
	Line   int    // 1-based line number within File
	Reason string
}

func (e *VerifyError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Reason)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// Verify walks one log and checks every line's hash and that each entry's
// prev is the previous entry's hash. It returns the number of entries and the
// last hash. The first entry's prev is taken on trust, because a single file
// cannot know what came before it (VerifyFiles checks that across files).
func Verify(r io.Reader) (n int, last string, err error) {
	return verifyStream(r, "", "", false)
}

// verifyStream verifies r. If linked, the first entry's prev must equal prev.
func verifyStream(r io.Reader, file, prev string, linked bool) (n int, last string, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	last = prev
	for lineNo := 1; ; lineNo++ {
		line, rerr := readLine(br, MaxLineBytes+1)
		if errors.Is(rerr, errLineTooLong) {
			return n, "", &VerifyError{file, lineNo, fmt.Sprintf("line longer than %d bytes", MaxLineBytes)}
		}
		if rerr != nil && rerr != io.EOF {
			return n, "", rerr
		}
		if len(line) == 0 { // clean EOF
			return n, last, nil
		}
		if line[len(line)-1] != '\n' {
			return n, "", &VerifyError{file, lineNo, "truncated: last line has no newline"}
		}
		p, h, reason := checkLine(line[:len(line)-1])
		if reason != "" {
			return n, "", &VerifyError{file, lineNo, reason}
		}
		if (n > 0 || linked) && p != last {
			return n, "", &VerifyError{file, lineNo, "prev does not match the previous entry's hash (an entry was removed, inserted or reordered)"}
		}
		n++
		last = h
		if rerr == io.EOF {
			return n, last, nil
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine returns the next line including its '\n' (without one only at
// EOF). It never holds more than limit bytes.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > limit {
			return nil, errLineTooLong
		}
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, err
	}
}

// lastHashOf checks the last line of a file of the given size and returns its
// hash ("" for an empty file). It reads backwards from the end, so opening a
// 50 MiB log costs one line, not the whole file.
func lastHashOf(r io.ReaderAt, size int64) (string, error) {
	if size == 0 {
		return "", nil
	}
	var nl [1]byte
	if _, err := r.ReadAt(nl[:], size-1); err != nil {
		return "", err
	}
	if nl[0] != '\n' {
		return "", errors.New("last line is truncated (no newline); run `rover log --verify`")
	}
	end := size - 1 // the last line is [start, end)
	start := int64(0)
	const block = 64 << 10
	buf := make([]byte, block)
	for pos := end; pos > 0; {
		k := min(int64(block), pos)
		if _, err := r.ReadAt(buf[:k], pos-k); err != nil {
			return "", err
		}
		if i := bytes.LastIndexByte(buf[:k], '\n'); i >= 0 {
			start = pos - k + int64(i) + 1
			break
		}
		pos -= k
		if end-pos > MaxLineBytes {
			return "", errors.New("last line is too long")
		}
	}
	line := make([]byte, end-start)
	if _, err := r.ReadAt(line, start); err != nil {
		return "", err
	}
	_, h, reason := checkLine(line)
	if reason != "" {
		return "", fmt.Errorf("last entry is damaged (%s); run `rover log --verify`", reason)
	}
	return h, nil
}

// rotatedName is <stem>-<ts>.jsonl, or <stem>-<ts>-<n>.jsonl for n > 0.
func rotatedName(stem, ts string, n int) string {
	if n == 0 {
		return stem + "-" + ts + ".jsonl"
	}
	return stem + "-" + ts + "-" + strconv.Itoa(n) + ".jsonl"
}

type rotatedKey struct {
	ts string
	n  int
}

// parseRotated parses a rotated file name for the log called name. ok is
// false if the name is not a rotated file of that log.
func parseRotated(name, file string) (k rotatedKey, ok bool) {
	stem := strings.TrimSuffix(name, ".jsonl")
	rest, found := strings.CutPrefix(file, stem+"-")
	if !found {
		return k, false
	}
	rest, found = strings.CutSuffix(rest, ".jsonl")
	if !found {
		return k, false
	}
	ts, num, hasNum := strings.Cut(rest, "-")
	if _, err := time.Parse(rotateLayout, ts); err != nil || len(ts) != len(rotateLayout) {
		return k, false
	}
	k.ts = ts
	if hasNum {
		n, err := strconv.Atoi(num)
		if err != nil || n <= 0 || strconv.Itoa(n) != num {
			return k, false
		}
		k.n = n
	}
	return k, true
}

// rotatedFiles lists the rotated files of the log called name, oldest first.
// A file that looks rotated (<stem>-*.jsonl) but has an unexpected name is an
// error: we cannot tell where it belongs in the chain, so we refuse to guess.
func rotatedFiles(root *os.Root, name string) ([]string, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	ents, err := d.ReadDir(-1)
	_ = d.Close() // read-only
	if err != nil {
		return nil, err
	}
	stem := strings.TrimSuffix(name, ".jsonl")
	type rf struct {
		name string
		key  rotatedKey
	}
	var out []rf
	for _, e := range ents {
		fn := e.Name()
		if !strings.HasPrefix(fn, stem+"-") || !strings.HasSuffix(fn, ".jsonl") {
			continue
		}
		k, ok := parseRotated(name, fn)
		if !ok {
			return nil, fmt.Errorf("unexpected file %q next to the audit log (rotated logs are named %s)", fn, rotatedName(stem, rotateLayout, 0))
		}
		out = append(out, rf{fn, k})
	}
	slices.SortFunc(out, func(a, b rf) int {
		if c := strings.Compare(a.key.ts, b.key.ts); c != 0 {
			return c
		}
		return a.key.n - b.key.n
	})
	names := make([]string, len(out))
	for i, f := range out {
		names[i] = f.name
	}
	return names, nil
}

// VerifyFiles verifies the whole chain in dir: the rotated files
// audit-*.jsonl, oldest first, then audit.jsonl, carrying the chain across
// files. The oldest file's first entry must have prev "" (the start of the
// chain), so deleting old files is detected too. It returns the total number
// of entries and the last hash.
func VerifyFiles(dir string) (n int, last string, err error) {
	const name = "audit.jsonl"
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = root.Close() }()

	files, err := rotatedFiles(root, name)
	if err != nil {
		return 0, "", err
	}
	if _, err := root.Lstat(name); err == nil {
		files = append(files, name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, "", err
	}
	if len(files) == 0 {
		return 0, "", fmt.Errorf("no audit log in %s: %w", dir, fs.ErrNotExist)
	}

	for _, fn := range files {
		f, err := root.Open(fn)
		if err != nil {
			return n, "", err
		}
		k, h, err := verifyStream(f, filepath.Join(dir, fn), last, true)
		_ = f.Close() // read-only
		n += k
		if err != nil {
			return n, "", err
		}
		last = h
	}
	return n, last, nil
}
