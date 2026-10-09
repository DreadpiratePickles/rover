package policy

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// policies200 generates 200 permits shaped like real ones: a scope on a
// concrete tool plus a condition on labels, session and arguments.
func policies200() string {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, `@id("p%d")
permit (principal, action == Action::"call_tool", resource == Tool::"srv%d/tool%d")
when { !context.session.saw_untrusted && context.time.hour >= 0 && !resource.labels.contains("egress") };
`, i, i%20, i)
	}
	return b.String()
}

func benchInput() Input {
	in := input(DirC2S, toolsCall("1", "tool199", `{"path":"/tmp/x","n":3,"tags":["a","b"]}`))
	in.Server = "srv19"
	return in
}

func BenchmarkDecide200(b *testing.B) {
	e := mustLoad(b, policies200())
	in := benchInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Decide(in)
	}
}

func TestDecideLatency(t *testing.T) {
	// Arrange
	const calls = 2000
	e := mustLoad(t, policies200())
	in := benchInput()
	if out := e.Decide(in); out.Action != "forward" {
		t.Fatalf("benchmark input is not permitted: %+v", out)
	}
	durations := make([]time.Duration, calls)

	// Act
	for i := range durations {
		start := time.Now()
		_ = e.Decide(in)
		durations[i] = time.Since(start)
	}

	// Assert
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p99 := durations[calls*99/100]
	t.Logf("Decide with 200 policies: p50 %v, p99 %v", durations[calls/2], p99)
	if p99 >= 5*time.Millisecond {
		t.Fatalf("p99 %v, want < 5ms", p99)
	}
}
