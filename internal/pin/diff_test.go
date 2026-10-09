package pin

import (
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	got := UnifiedDiff("a\nb\nc\n", "a\nB\nc\nd\n")
	want := "--- pinned\n+++ latest\n@@ -1,3 +1,4 @@\n a\n-b\n+B\n c\n+d\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestUnifiedDiffOfNewTool(t *testing.T) {
	if got := UnifiedDiff("", "a\n"); got != "--- pinned\n+++ latest\n@@ -0,0 +1,1 @@\n+a\n" {
		t.Fatalf("got %q", got)
	}
}

func TestUnifiedDiffIsCapped(t *testing.T) {
	big := strings.Repeat("x", 100) + "\n"
	got := UnifiedDiff("", strings.Repeat(big, 100))
	if len(got) > MaxDiff || !strings.HasSuffix(got, "cut at 4 KiB)\n") {
		t.Fatalf("len %d, tail %q", len(got), got[len(got)-30:])
	}
}

func TestTerminalSafe(t *testing.T) {
	got := TerminalSafe("ok\x1b[31mred\u009b\u202eevil\nnext\t.")
	if got != "ok\\u001b[31mred\\u009b\\u202eevil\nnext\t." {
		t.Fatalf("got %q", got)
	}
}
