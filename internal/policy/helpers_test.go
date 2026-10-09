package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// fixedNow is the injected clock for tests: Wednesday 2026-10-07 14:30 UTC.
var fixedNow = time.Date(2026, 10, 7, 14, 30, 0, 0, time.UTC)

func mustLoad(t testing.TB, src string) *Engine {
	t.Helper()
	e, err := Load([]byte(src), "test.cedar", policyfiles.Schema)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return e
}

// input builds an enforce-mode Input for server "echo" from a raw line.
func input(dir, line string) Input {
	return Input{
		Mode:      ModeEnforce,
		Client:    "claude-code",
		Server:    "echo",
		Transport: "stdio",
		Dir:       dir,
		Msg:       jsonrpc.Parse([]byte(line)),
		Now:       fixedNow,
	}
}

func toolsCall(id, tool, args string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func mustContain(t *testing.T, haystack []byte, needle string) {
	t.Helper()
	if !strings.Contains(string(haystack), needle) {
		t.Fatalf("%s\ndoes not contain %q", haystack, needle)
	}
}
