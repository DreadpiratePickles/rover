package dlp

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

const resultSize = 64 << 10

// realisticResult is about 64 KB of what a fetch, file or CI tool returns:
// prose, links, code, hashes, a config with one fake key.
func realisticResult() []byte {
	chunk := "# Release notes\n\nThe service now caches responses. See the [design doc](https://example.com/docs/design) " +
		"and ![diagram](https://example.com/img/arch.png). Run `make test` before you submit a pull request.\n" +
		"func load(path string) ([]byte, error) { token := getToken(); return os.ReadFile(path) } // TODO\n" +
		"commit 3b46f4b1c9a0d2e8f7a6b5c4d3e2f1a0b9c8d7e6 sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n" +
		"request 550e8400-e29b-41d4-a716-446655440000 took 42ms; password=hunter2hunter2 # fixture\n" +
		"Contact: alice@example.com, https://example.com/search?q=cats&page=2 — naïve café, 日本語.\n\n"
	var b strings.Builder
	for b.Len() < resultSize {
		b.WriteString(chunk)
	}
	return []byte(b.String()[:resultSize])
}

// TestFindLatency64KB is the plan's budget (§6 M10: one pass, <= 2 ms on a
// 64 KB result), as a load-tolerant guard like M5's: median <= 2 ms, p99 <=
// 20 ms; under -race (every memory access instrumented) median <= 15 ms.
// ROVER_TIMING_STRICT=1 makes the p99 bound 2 ms too, for a quiet machine.
// BenchmarkFind64KB (without -race) is the real number.
func TestFindLatency64KB(t *testing.T) {
	const runs = 300
	median, p99Max := 2*time.Millisecond, 20*time.Millisecond
	if os.Getenv("ROVER_TIMING_STRICT") == "1" {
		p99Max = 2 * time.Millisecond
	}
	if raceBuild {
		median, p99Max = 15*time.Millisecond, 60*time.Millisecond
	}
	d, text := New(), realisticResult()
	durations := make([]time.Duration, runs)
	for i := range durations {
		start := time.Now()
		if ms := d.Find(text); len(ms) == 0 {
			t.Fatal("the fixture password must be found")
		}
		durations[i] = time.Since(start)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50, p99 := durations[runs/2], durations[runs*99/100]
	t.Logf("Find on a 64 KB result (race=%v): p50 %v, p99 %v", raceBuild, p50, p99)
	if p50 > median || p99 > p99Max {
		t.Fatalf("p50 %v (max %v), p99 %v (max %v)", p50, median, p99, p99Max)
	}
}

// TestWorstCaseInputsStayLinear: 64 KB of each input that could make a
// detector slow may take at most 8x as long as 16 KB (linear is 4x).
func TestWorstCaseInputsStayLinear(t *testing.T) {
	limit := 50 * time.Millisecond
	if raceBuild {
		limit = 500 * time.Millisecond
	}
	units := []string{
		"AKIA", "ghp_", "xoxb-", "eyJ", "eyJhbGciOiJub25lIn0.", "-----BEGIN PRIVATE KEY-----", "-----BEGIN ", "-----BEGIN CERTIFICATE-----\n", "-----END ",
		"password=", "token: \"", "secret", "Zx8Q2mN7pL4vR1tK9sW3yB6cF0hJ5gD8aE2uI7oP.", "a", "://", "base64,",
		"hooks.slack.com/services/", "sk_live_", "aws ", "=",
	}
	d := New()
	fastest := func(text []byte) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			_ = d.Find(text)
			best = min(best, time.Since(start))
		}
		return best
	}
	for _, u := range units {
		fill := func(n int) []byte { return []byte(strings.Repeat(u, n/len(u)+1)[:n]) }
		small, big := fastest(fill(resultSize/4)), fastest(fill(resultSize))
		if big > limit || big > 8*small+5*time.Millisecond {
			t.Errorf("%q: 16 KB %v, 64 KB %v (limit %v)", u, small, big, limit)
		}
	}
}

func BenchmarkFind64KB(b *testing.B) {
	d, text := New(), realisticResult()
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		_ = d.Find(text)
	}
}

func BenchmarkRedactJSON64KB(b *testing.B) {
	d := New()
	raw := []byte(`{"content":[{"type":"text","text":` + string(EncodeForTest(realisticResult())) + `}]}`)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := RedactJSON(d, raw); err != nil {
			b.Fatal(err)
		}
	}
}
