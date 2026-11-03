package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Result is what Verify found.
type Result struct {
	Entries   int       // lines checked
	LastHash  string    // hash of the final entry, "" if the log is empty
	LastTime  time.Time // time of the final entry
	FirstPrev string    // Prev of the first entry; non-empty means it continues an earlier file
	File      string    // which file the problem is in (VerifyChain only)
	Line      int       // 1-based line of the first problem, 0 if none
	Err       error     // nil when the chain is intact
}

// ChainFiles lists the log files for path in chain order: rotated files
// (path.<timestamp>, sorted) followed by the live file.
func ChainFiles(path string) ([]string, error) {
	rotated, err := filepath.Glob(path + ".*")
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(rotated)+1)
	for _, f := range rotated {
		// Rotated files are named path.<UTC timestamp>; anything else that
		// happens to share the prefix is not part of the chain.
		suffix := strings.TrimPrefix(f, path+".")
		if !isTimestamp(suffix) {
			continue
		}
		files = append(files, f)
	}
	sort.Strings(files)
	if _, err := os.Stat(path); err == nil {
		files = append(files, path)
	}
	return files, nil
}

// VerifyChain checks a whole sequence of files as one chain: the first
// entry of the first file must have no predecessor, each file must continue
// the previous one, and, when anchor is non-empty, the anchored hash must be
// one of the hashes in the chain. A chain whose head or tail was cut fails.
func VerifyChain(files []string, anchor string) Result {
	var total Result
	prev := ""
	anchorSeen := anchor == ""
	for i, name := range files {
		f, err := os.Open(name) //nolint:gosec // G304: Rover-owned audit-log path
		if err != nil {
			return Result{File: name, Err: fmt.Errorf("%w: %v", ErrChainBroken, err)}
		}
		res := verify(f, &anchorSeen, anchor)
		_ = f.Close()
		res.File = name
		if res.Err != nil {
			return res
		}
		if res.Entries == 0 {
			continue
		}
		if i == 0 && res.FirstPrev != "" {
			res.Line, res.Err = 1, fmt.Errorf("%w: first entry claims a predecessor %q but this is the oldest file (head of the log removed?)", ErrChainBroken, res.FirstPrev)
			return res
		}
		if i > 0 && res.FirstPrev != prev {
			res.Line, res.Err = 1, fmt.Errorf("%w: file does not continue the previous one (prev %q, want %q)", ErrChainBroken, res.FirstPrev, prev)
			return res
		}
		prev = res.LastHash
		total.Entries += res.Entries
		total.LastHash = res.LastHash
		if total.FirstPrev == "" && i == 0 {
			total.FirstPrev = res.FirstPrev
		}
	}
	if !anchorSeen {
		total.Err = fmt.Errorf("%w: anchored hash %.12s... is not in the log (tail of the log removed?)", ErrChainBroken, anchor)
	}
	return total
}

// ErrChainBroken is wrapped by every verification failure.
var ErrChainBroken = errors.New("audit chain broken")

// MaxLine bounds a single audit line while verifying (bodies are capped by
// the proxy's 16 MiB message limit, plus metadata).
const MaxLine = 17 << 20

// Verify walks one file and reports the first line whose bytes, hash or
// link to the previous entry do not match. It does not know about other
// files or the anchor; use VerifyChain for the whole log.
func Verify(r io.Reader) Result {
	seen := true
	return verify(r, &seen, "")
}

func verify(r io.Reader, anchorSeen *bool, anchor string) Result {
	var res Result
	br := bufioReader(r)
	prev := ""
	for n := 1; ; n++ {
		line, err := readLine(br)
		if len(bytes.TrimSpace(line)) > 0 {
			var e Entry
			if uerr := json.Unmarshal(line, &e); uerr != nil {
				return fail(res, n, fmt.Errorf("%w: not valid JSON: %v", ErrChainBroken, uerr))
			}
			if n == 1 {
				res.FirstPrev = e.Prev
				prev = e.Prev
			}
			if e.Prev != prev {
				return fail(res, n, fmt.Errorf("%w: prev %q does not match previous hash %q", ErrChainBroken, e.Prev, prev))
			}
			claimed := e.Hash
			canon, hash, eerr := encode(e)
			if eerr != nil {
				return fail(res, n, fmt.Errorf("%w: %v", ErrChainBroken, eerr))
			}
			if hash != claimed {
				return fail(res, n, fmt.Errorf("%w: hash %q does not match contents (%q)", ErrChainBroken, claimed, hash))
			}
			if !bytes.Equal(bytes.TrimRight(canon, "\n"), bytes.TrimRight(line, "\r\n")) {
				return fail(res, n, fmt.Errorf("%w: line is not in canonical form (edited after writing)", ErrChainBroken))
			}
			prev = hash
			res.Entries++
			res.LastHash, res.LastTime = hash, e.Time
			if hash == anchor {
				*anchorSeen = true
			}
		}
		if errors.Is(err, io.EOF) {
			return res
		}
		if err != nil {
			return fail(res, n, fmt.Errorf("%w: %v", ErrChainBroken, err))
		}
	}
}

// isTimestamp matches the rotation suffix layout 20060102T150405.000000000Z.
func isTimestamp(s string) bool {
	_, err := time.Parse("20060102T150405.000000000Z", s)
	return err == nil
}

func fail(res Result, line int, err error) Result {
	res.Line, res.Err = line, err
	return res
}
