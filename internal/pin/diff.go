package pin

import (
	"fmt"
	"strings"
	"unicode"
)

// Diff limits. A description can be any size and say anything; the diff is
// for a human deciding whether to approve, not an archive.
const (
	maxDiffChanged = 40      // changed lines shown; the rest are counted
	diffContext    = 2       // unchanged lines around each change
	MaxDiff        = 8 << 10 // hard byte cap on top of maxDiffChanged
	wrapWidth      = 100     // diff view: break lines after this many runes
	maxDiffLines   = 4000    // the LCS is quadratic: above this, replace whole
)

// DiffOf is the unified diff from p's pinned definition to the one the
// server sent last.
func DiffOf(p Pinned) string {
	if p.Latest == "" && p.Problem != "" {
		return "(the latest definition has no canonical form: " + p.Problem + ")\n"
	}
	return UnifiedDiff(Pretty([]byte(p.Canonical)), Pretty([]byte(p.LatestCanonical)))
}

// UnifiedDiff diffs a ("pinned") and b ("latest") line by line, over a
// wrapped view of both: every line is broken after each sentence end and
// after wrapWidth runes, so a change at the end of a long description shows
// up as the sentence that changed, not as one 6 KiB line. The wrapping is for
// the diff only; the digest covers the canonical bytes. At most
// maxDiffChanged changed lines are shown, with diffContext lines of context.
func UnifiedDiff(a, b string) string {
	al, bl := wrapLines(a), wrapLines(b)
	ops := diffOps(al, bl)
	var sb strings.Builder
	sb.WriteString("--- pinned\n+++ latest\n")
	shown, total := 0, 0
	for _, op := range ops {
		if op[0] != ' ' {
			total++
		}
	}
	for _, h := range hunks(ops) {
		if shown >= maxDiffChanged {
			break
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", hunkRange(h.aStart, h.aLen), hunkRange(h.bStart, h.bLen))
		for _, op := range ops[h.from:h.to] {
			if op[0] != ' ' {
				if shown >= maxDiffChanged {
					break
				}
				shown++
			}
			if sb.Len()+len(op)+1 > MaxDiff {
				shown = -1
				break
			}
			sb.WriteString(op)
			sb.WriteByte('\n')
		}
		if shown < 0 {
			break
		}
	}
	switch {
	case shown < 0:
		sb.WriteString("... (diff cut at 8 KiB)\n")
	case total > shown:
		fmt.Fprintf(&sb, "... %d more changed lines\n", total-shown)
	}
	return sb.String()
}

type hunk struct{ from, to, aStart, aLen, bStart, bLen int }

// hunks groups ops into runs of changes, merging changes less than
// 2*diffContext unchanged lines apart, with diffContext lines around each.
func hunks(ops []string) []hunk {
	var out []hunk
	for i := 0; i < len(ops); {
		if ops[i][0] == ' ' {
			i++
			continue
		}
		end := i // last changed line of this hunk
		for j := i; j < len(ops); {
			if ops[j][0] != ' ' {
				end = j
				j++
				continue
			}
			k := j
			for k < len(ops) && ops[k][0] == ' ' {
				k++
			}
			if k == len(ops) || k-j > 2*diffContext {
				break
			}
			j = k
		}
		to := min(len(ops), end+1+diffContext)
		out = append(out, span(ops, max(0, i-diffContext), to))
		i = to
	}
	return out
}

func span(ops []string, from, to int) hunk {
	h := hunk{from: from, to: to, aStart: 1, bStart: 1}
	for _, op := range ops[:from] {
		if op[0] != '+' {
			h.aStart++
		}
		if op[0] != '-' {
			h.bStart++
		}
	}
	for _, op := range ops[from:to] {
		if op[0] != '+' {
			h.aLen++
		}
		if op[0] != '-' {
			h.bLen++
		}
	}
	return h
}

// hunkRange is "start,n", or "start-1,0" for an empty side, as diff -u writes it.
func hunkRange(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start-1)
	}
	return fmt.Sprintf("%d,%d", start, n)
}

// wrapLines splits s into lines, then breaks each after every sentence end
// (". ", "! ", "? ") and after wrapWidth runes. Continuation lines are
// indented two more spaces than their line.
func wrapLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		cont := line[:len(line)-len(strings.TrimLeft(line, " "))] + "  "
		rest, prefix := line, ""
		for {
			cut := breakAt(rest)
			if cut >= len(rest) {
				out = append(out, prefix+rest)
				break
			}
			out = append(out, prefix+rest[:cut])
			rest, prefix = rest[cut:], cont
		}
	}
	return out
}

// breakAt returns the byte offset after the first sentence end, or after
// wrapWidth runes, whichever comes first (len(s) if neither).
func breakAt(s string) int {
	runes := 0
	for i, r := range s {
		if runes == wrapWidth {
			return i
		}
		runes++
		if (r == '.' || r == '!' || r == '?') && i+1 < len(s) && s[i+1] == ' ' && i+2 < len(s) {
			return i + 2
		}
	}
	return len(s)
}

// diffOps returns a's and b's lines prefixed " ", "-" or "+". The common
// prefix and suffix are trimmed first, so a long tool with a small change
// stays cheap; the middle is diffed by longest common subsequence.
func diffOps(a, b []string) []string {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	out := make([]string, 0, len(a)+len(b))
	for _, l := range a[:pre] {
		out = append(out, " "+l)
	}
	out = append(out, lcsOps(a[pre:len(a)-suf], b[pre:len(b)-suf])...)
	for _, l := range a[len(a)-suf:] {
		out = append(out, " "+l)
	}
	return out
}

func lcsOps(a, b []string) []string {
	var out []string
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		for _, l := range a {
			out = append(out, "-"+l)
		}
		for _, l := range b {
			out = append(out, "+"+l)
		}
		return out
	}
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, " "+a[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "-"+a[i])
			i++
		default:
			out = append(out, "+"+b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, "-"+a[i])
	}
	for ; j < len(b); j++ {
		out = append(out, "+"+b[j])
	}
	return out
}

// TerminalSafe escapes runes that could drive or mislead a terminal: C0 and
// C1 controls other than newline and tab (ESC starts escape sequences; U+009B
// is a one-byte CSI on some terminals) and the bidirectional overrides used
// in "Trojan Source" tricks. Tool names and descriptions come from the
// server, which may be hostile; `rover pin list` prints them through this.
func TerminalSafe(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
