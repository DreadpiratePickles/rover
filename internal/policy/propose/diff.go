package propose

import (
	"fmt"
	"strings"
)

// Diff limits: policies are small; above maxDiffLines the LCS (quadratic)
// is skipped and the whole file is shown as replaced.
const (
	diffContext  = 3
	maxDiffLines = 5000
)

// UnifiedDiff returns the unified diff (diff -u style) from a to b, or ""
// when they are equal.
func UnifiedDiff(aName, bName string, a, b []byte) string {
	al, bl := splitLines(string(a)), splitLines(string(b))
	ops := lineOps(al, bl)
	changed := false
	for _, op := range ops {
		if op.kind != ' ' {
			changed = true
			break
		}
	}
	if !changed {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("--- " + aName + "\n+++ " + bName + "\n")
	for _, h := range hunks(ops) {
		sb.WriteString(h)
	}
	return sb.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type op struct {
	kind   byte // ' ', '-', '+'
	text   string
	ai, bi int // line numbers (0-based) in a and b before this op
}

// lineOps is the edit script from a to b (longest common subsequence).
func lineOps(a, b []string) []op {
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		var ops []op
		for i, l := range a {
			ops = append(ops, op{'-', l, i, 0})
		}
		for j, l := range b {
			ops = append(ops, op{'+', l, len(a), j})
		}
		return ops
	}
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if strings.TrimSuffix(a[i], "\n") == strings.TrimSuffix(b[j], "\n") {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && strings.TrimSuffix(a[i], "\n") == strings.TrimSuffix(b[j], "\n"):
			ops = append(ops, op{' ', a[i], i, j})
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', a[i], i, j})
			i++
		default:
			ops = append(ops, op{'+', b[j], i, j})
			j++
		}
	}
	return ops
}

// hunks groups ops into @@ hunks with diffContext lines of context.
func hunks(ops []op) []string {
	var out []string
	for start := 0; start < len(ops); {
		for start < len(ops) && ops[start].kind == ' ' {
			start++
		}
		if start == len(ops) {
			break
		}
		from := max(0, start-diffContext)
		end, quiet := start, 0
		for end < len(ops) && quiet <= 2*diffContext {
			if ops[end].kind == ' ' {
				quiet++
			} else {
				quiet = 0
			}
			end++
		}
		end -= max(0, quiet-diffContext)
		out = append(out, hunk(ops[from:end]))
		start = end
	}
	return out
}

func hunk(ops []op) string {
	na, nb := 0, 0
	var body strings.Builder
	for _, o := range ops {
		if o.kind != '+' {
			na++
		}
		if o.kind != '-' {
			nb++
		}
		line := o.text
		if !strings.HasSuffix(line, "\n") {
			line += "\n\\ No newline at end of file\n"
		}
		body.WriteString(string(o.kind) + line)
	}
	return fmt.Sprintf("@@ -%s +%s @@\n%s", rangeOf(ops[0].ai, na), rangeOf(ops[0].bi, nb), body.String())
}

func rangeOf(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}
