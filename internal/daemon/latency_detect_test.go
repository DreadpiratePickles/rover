package daemon

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// cleanResult64KB is a tools/call result carrying about 64 KB of ordinary text.
func cleanResult64KB(id string) []byte {
	chunk := "The service now caches responses. See the [design doc](https://example.com/docs/design). " +
		"Run make test before you submit a pull request; the previous section explains the setup.\\n"
	text := strings.Repeat(chunk, (64<<10)/len(chunk)+1)[:64<<10]
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[{"type":"text","text":"` + text + `"}],"isError":false}}`)
}

// medianResultDecide measures decide on a 64 KB clean tools/call result.
func medianResultDecide(t *testing.T, disable bool) time.Duration {
	t.Helper()
	s := start(t, Options{Audit: audit.New(&bytes.Buffer{}), Policy: engine(t, detectPolicy), Config: enforce(), DisableDetection: disable})
	c, err := ipc.Dial(s.Addr(), hello(1, "lat"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	const n = 150
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		decide(t, c, "c2s", call("7", "fetch"))
		res := cleanResult64KB("7")
		t0 := time.Now()
		v, _, err := c.Decide("s2c", res)
		lat = append(lat, time.Since(t0))
		if err != nil || v.Action != ipc.ActionForward {
			t.Fatalf("verdict %+v err %v", v, err)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat[n/2]
}

// TestDetectionAddsLittleToDecide is plan §6 M5's accept criterion at the
// daemon: detection may add at most 2 ms (10 ms under -race, which
// instruments every memory access) to the median decide on a 64 KB result.
func TestDetectionAddsLittleToDecide(t *testing.T) {
	budget := 2 * time.Millisecond
	if raceBuild {
		budget = 10 * time.Millisecond
	}
	off := medianResultDecide(t, true)
	on := medianResultDecide(t, false)
	t.Logf("decide on a 64 KB result: detection off %v, on %v, added %v (race=%v)", off, on, on-off, raceBuild)
	if on-off > budget {
		t.Fatalf("detection adds %v, budget %v", on-off, budget)
	}
}
