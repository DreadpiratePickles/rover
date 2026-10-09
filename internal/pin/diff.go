package pin

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxDiff caps a diff. A description can be any size and say anything; the
// diff is for a human deciding whether to approve, not an archive.
const MaxDiff = 4 << 10

// maxDiffLines bounds the line-by-line comparison (it is quadratic). Larger
// inputs are shown as a whole-file replacement.
const maxDiffLines = 2000

// DiffOf is the unified diff from p's pinned definition to the one the
// server sent last, both pretty-printed.
func DiffOf(p Pinned) string {
	if p.Latest == "" && p.Problem != "" {
		return "(the latest definition has no canonical form: " + p.Problem + ")\n"
	}
	return UnifiedDiff(Pretty([]byte(p.Canonical)), Pretty([]byte(p.LatestCanonical)))
}

// UnifiedDiff is a single-hunk unified diff of a ("pinned") and b
// ("latest") with full context, cut at MaxDiff bytes.
func UnifiedDiff(a, b string) string {
	al, bl := splitLines(a), splitLines(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- pinned\n+++ latest\n@@ -%s +%s @@\n", hunkRange(len(al)), hunkRange(len(bl)))
	for _, l := range diffLines(al, bl) {
		if sb.Len()+len(l)+1 > MaxDiff {
			sb.WriteString("... (diff cut at 4 KiB)\n")
			break
		}
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// hunkRange is "1,n", or "0,0" for an empty side, as diff -u writes it.
func hunkRange(n int) string {
	if n == 0 {
		return "0,0"
	}
	return fmt.Sprintf("1,%d", n)
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// diffLines returns a's and b's lines prefixed " ", "-" or "+", from a
// longest common subsequence.
func diffLines(a, b []string) []string {
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		out := make([]string, 0, len(a)+len(b))
		for _, l := range a {
			out = append(out, "-"+l)
		}
		for _, l := range b {
			out = append(out, "+"+l)
		}
		return out
	}
	// lcs[i][j] = LCS length of a[i:] and b[j:].
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
	var out []string
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
