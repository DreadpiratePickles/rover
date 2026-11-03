package clients

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/pin"
)

// diffContext is the number of unchanged lines shown around each change.
const diffContext = 2

// unifiedDiff renders edits to orig as a unified diff. Because the edits
// are known exactly, no diff algorithm is needed: each group of edits
// touches a run of lines, which is shown removed and then re-added with
// the edits applied. The text is made terminal-safe: a config can hold
// anything, including escape sequences.
func unifiedDiff(path string, orig []byte, edits []edit) string {
	if len(edits) == 0 {
		return ""
	}
	starts := lineStarts(orig)
	lineOf := func(off int) int { return sort.Search(len(starts), func(i int) bool { return starts[i] > off }) - 1 }
	es := append([]edit(nil), edits...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].start < es[j].start })

	type group struct {
		first, last int // line range touched, inclusive
		edits       []edit
	}
	var groups []group
	for _, e := range es {
		first, last := lineOf(e.start), lineOf(max(e.start, e.end-1))
		if n := len(groups); n > 0 && first-groups[n-1].last <= 2*diffContext+1 {
			g := &groups[n-1]
			g.last = max(g.last, last)
			g.edits = append(g.edits, e)
			continue
		}
		groups = append(groups, group{first: first, last: last, edits: []edit{e}})
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s (rover)\n", path, path)
	lines := len(starts)
	shift := 0 // new-file line number minus old, so far
	for _, g := range groups {
		from, to := max(0, g.first-diffContext), min(lines-1, g.last+diffContext)
		touched := map[int]bool{}
		for _, e := range g.edits {
			for l := lineOf(e.start); l <= lineOf(max(e.start, e.end-1)); l++ {
				touched[l] = true
			}
		}
		var body strings.Builder
		oldN, newN := 0, 0
		for l := from; l <= to; {
			if !touched[l] {
				writeLines(&body, " ", splitLines(orig[starts[l]:lineEnd(orig, starts, l)]))
				oldN, newN, l = oldN+1, newN+1, l+1
				continue
			}
			run := l
			for run+1 <= to && touched[run+1] {
				run++
			}
			lo, hi := starts[l], lineEnd(orig, starts, run)
			var local []edit
			for _, e := range g.edits {
				if e.start >= lo && e.start < hi || e.start == hi && e.end == hi && hi == len(orig) {
					local = append(local, edit{start: e.start - lo, end: e.end - lo, text: e.text})
				}
			}
			changed, err := applyEdits(orig[lo:hi], local)
			if err != nil {
				return "(diff unavailable: " + err.Error() + ")\n"
			}
			oldLines, newLines := splitLines(orig[lo:hi]), splitLines(changed)
			writeLines(&body, "-", oldLines)
			writeLines(&body, "+", newLines)
			oldN, newN, l = oldN+len(oldLines), newN+len(newLines), run+1
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", from+1, oldN, from+1+shift, newN)
		sb.WriteString(body.String())
		shift += newN - oldN
	}
	return pin.TerminalSafe(sb.String())
}

// lineStarts returns the byte offset at which every line starts.
func lineStarts(b []byte) []int {
	starts := []int{0}
	for i, c := range b {
		if c == '\n' && i+1 < len(b) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// lineEnd is the offset just past line n (including its newline).
func lineEnd(b []byte, starts []int, n int) int {
	if n+1 < len(starts) {
		return starts[n+1]
	}
	return len(b)
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(sb *strings.Builder, mark string, lines []string) {
	for _, l := range lines {
		sb.WriteString(mark)
		sb.WriteString(strings.TrimSuffix(l, "\n"))
		sb.WriteByte('\n')
	}
}

// wholeDiff diffs two whole files by trimming their common leading and
// trailing lines; the middle is shown removed and re-added. Restore uses
// it: a backup is not a set of edits.
func wholeDiff(path string, a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	al, bl := splitLines(a), splitLines(b)
	p := 0
	for p < len(al) && p < len(bl) && al[p] == bl[p] {
		p++
	}
	s := 0
	for s < len(al)-p && s < len(bl)-p && al[len(al)-1-s] == bl[len(bl)-1-s] {
		s++
	}
	from := max(0, p-diffContext)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s (backup)\n", path, path)
	ctxAfter := min(s, diffContext)
	fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", from+1, len(al)-s-from+ctxAfter, from+1, len(bl)-s-from+ctxAfter)
	writeLines(&sb, " ", al[from:p])
	writeLines(&sb, "-", al[p:len(al)-s])
	writeLines(&sb, "+", bl[p:len(bl)-s])
	writeLines(&sb, " ", al[len(al)-s:len(al)-s+ctxAfter])
	return pin.TerminalSafe(sb.String())
}
