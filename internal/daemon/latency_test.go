package daemon

import (
	"io"
	"slices"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// Plan §4.3: a decide round trip must stay under 5 ms p99 with rules-only
// detection, and CI fails above 10 ms. Measured over a real Unix socket,
// with a real (hash-chained) audit logger writing to io.Discard.
const latencyBudget = 10 * time.Millisecond

var smallMsg = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`)

func TestDecideLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	f := start(t, Options{Audit: audit.New(io.Discard)})
	c, _ := f.client(t, 1000, "echo")
	const warmup, n = 200, 2000
	for i := 0; i < warmup; i++ {
		if _, err := c.Decide(proxy.ClientToServer, smallMsg); err != nil {
			t.Fatal(err)
		}
	}
	d := make([]time.Duration, n)
	for i := range d {
		start := time.Now()
		if _, err := c.Decide(proxy.ClientToServer, smallMsg); err != nil {
			t.Fatal(err)
		}
		d[i] = time.Since(start)
	}
	slices.Sort(d)
	p50, p99, maxD := d[n/2], d[n*99/100], d[n-1]
	t.Logf("decide round trip over %d calls: p50=%v p99=%v max=%v", n, p50, p99, maxD)
	if p99 > latencyBudget {
		t.Fatalf("p99 %v exceeds the %v budget", p99, latencyBudget)
	}
}

func BenchmarkDecide(b *testing.B) {
	f := start(b, Options{Audit: audit.New(io.Discard)})
	c, _ := f.client(b, 1000, "echo")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Decide(proxy.ClientToServer, smallMsg); err != nil {
			b.Fatal(err)
		}
	}
}
