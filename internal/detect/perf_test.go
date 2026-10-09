package detect

import (
	"sort"
	"strings"
	"testing"
	"time"
)

const resultSize = 64 << 10

// realisticResult is about 64 KB of what a fetch or file tool returns:
// prose, markdown, links, code, a log line with colours.
func realisticResult() []byte {
	chunk := "# Release notes\n\nThe service now caches responses. See the [design doc](https://example.com/docs/design) " +
		"and ![diagram](https://example.com/img/arch.png). Run `make test` before you submit a pull request; " +
		"the previous section explains the setup. \x1b[32mPASS\x1b[0m internal/cache 0.42s\n" +
		"func load(path string) ([]byte, error) { return os.ReadFile(path) } // TODO: limits\n" +
		"Contact: alice@example.com, https://example.com/search?q=cats&page=2 — naïve café, 日本語.\n\n"
	var b strings.Builder
	for b.Len() < resultSize {
		b.WriteString(chunk)
	}
	return []byte(b.String()[:resultSize])
}

// TestScanLatency64KB is the plan's accept criterion (§6 M5: the rule scan
// adds no more than 2 ms p99 to a decide on a 64 KB result), written as a
// load-tolerant guard like M2's latency tests: the median must meet the
// 2 ms budget, the p99 only 10x that, so a machine busy with -race and
// fuzzers does not fail it while a real regression (a quadratic rule) does.
// BenchmarkScan64KB is the real number.
func TestScanLatency64KB(t *testing.T) {
	// Arrange
	const (
		runs   = 300
		budget = 2 * time.Millisecond
	)
	sc := NewRules()
	text := realisticResult()
	durations := make([]time.Duration, runs)

	// Act
	for i := range durations {
		start := time.Now()
		_ = sc.Scan(KindToolResult, text)
		durations[i] = time.Since(start)
	}

	// Assert
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50, p99 := durations[runs/2], durations[runs*99/100]
	t.Logf("Scan of a 64 KB result: p50 %v, p99 %v, max %v", p50, p99, durations[runs-1])
	if p50 > budget {
		t.Fatalf("p50 %v, want <= %v", p50, budget)
	}
	if p99 > 10*budget {
		t.Fatalf("p99 %v, want <= %v", p99, 10*budget)
	}
}

func BenchmarkScan64KB(b *testing.B) {
	sc := NewRules()
	text := realisticResult()
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sc.Scan(KindToolResult, text)
	}
}

// TestWorstCaseInputsStayLinear feeds 64 KB of each input that could make a
// rule slow: a wall of the characters and words the rules key on. Go's
// regexp has no backtracking, the phrase window is bounded, searches that
// could repeat remember where they stopped and findings are capped, so the
// time must grow linearly: 64 KB may take at most 8x as long as 16 KB
// (linear is 4x, quadratic 16x), and stay under an absolute bound (generous
// under -race, which slows every memory access tenfold).
func TestWorstCaseInputsStayLinear(t *testing.T) {
	limit := 100 * time.Millisecond
	if raceBuild {
		limit = time.Second
	}
	fill := func(unit string, size int) []byte {
		return []byte(strings.Repeat(unit, size/len(unit)+1)[:size])
	}
	units := []string{
		"<", "ignore ", "ignore all ", "do not tell ", "when the ", "you must ", "before using ",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		"\u200b", "\u200d", "\U000E0041", "\U0001F3F4\U000E0067", "\x1b[", "\x1b]", "\x1b]0;x",
		"<!--", "](", "[](http://a?", "](https://a?b", "http://", "https://a.example/?" + strings.Repeat("x", 70) + " ",
		"<a hidden ", "display:", "~/.ssh/", ".env ", "send_email ",
	}
	sc := NewRules(WithKnownTools(map[string][]string{"x": {"send_email"}}))
	// fastest of 3: the least disturbed by other tests running in parallel
	fastest := func(kind Kind, text []byte) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			if fs := sc.Scan(kind, text); len(fs) > len(RuleIDs)*maxPerRule {
				t.Fatalf("%d findings", len(fs))
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	for _, unit := range units {
		// Resource and elicitation text take the tool_result code path.
		for _, kind := range []Kind{KindToolDescription, KindToolArgs, KindToolResult} {
			small, big := fastest(kind, fill(unit, resultSize/4)), fastest(kind, fill(unit, resultSize))
			if big > limit {
				t.Errorf("%q as %s: %v for 64 KB (limit %v)", unit, kind, big, limit)
			}
			if big > 8*small+10*time.Millisecond {
				t.Errorf("%q as %s: 16 KB %v, 64 KB %v: not linear", unit, kind, small, big)
			}
		}
	}
}
