package proxy

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
)

// Both directions of a session run in their own goroutine and share the
// pending map. This test drives them at once so `go test -race` actually
// exercises that sharing; the other tests run one direction at a time and
// would pass even with the lock removed.
func TestBothDirectionsConcurrently(t *testing.T) {
	s := NewSession("race", audit.New(io.Discard))
	var reqs, resps strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&reqs, `{"jsonrpc":"2.0","id":%d,"method":"ping"}`+"\n", i)
		fmt.Fprintf(&resps, `{"jsonrpc":"2.0","id":%d,"result":{}}`+"\n", i)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.Pump(strings.NewReader(reqs.String()), io.Discard, ClientToServer); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := s.Pump(strings.NewReader(resps.String()), io.Discard, ServerToClient); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
}
