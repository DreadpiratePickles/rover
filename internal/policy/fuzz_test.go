package policy

import (
	"testing"

	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// FuzzDecide feeds arbitrary lines to Decide: it must never panic, and a
// policed request must never be forwarded unless a permit fired.
func FuzzDecide(f *testing.F) {
	f.Add(toolsCall("1", "echo", `{"text":"hi"}`))
	f.Add(toolsCall("1", "echo", `{"a":{"a":{"a":1}},"a":2}`))
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x"}}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}`)
	e := mustLoad(f, permitEcho+"\n"+hideReadFile)
	f.Fuzz(func(t *testing.T, line string) {
		out := e.Decide(input(DirC2S, line))
		if out.Action == ipc.ActionForward && out.Reason == "" && len(out.RuleIDs) > 0 && !contains(out.RuleIDs, "allow-echo") {
			t.Fatalf("forwarded on %v", out.RuleIDs)
		}
		if out.Action != ipc.ActionForward && out.Action != ipc.ActionBlock {
			t.Fatalf("unexpected action %q", out.Action)
		}
	})
}

// FuzzFilterToolsList parses server-controlled tools/list results: it must
// never panic, and read_file must never survive a successful filter.
func FuzzFilterToolsList(f *testing.F) {
	f.Add(`{"tools":[{"name":"echo"},{"name":"read_file"}],"nextCursor":"x"}`)
	f.Add(`{"tools":[{"name":"read_file"}]}`)
	f.Add(`{"tools":null}`)
	e := mustLoad(f, hideReadFile)
	f.Fuzz(func(t *testing.T, result string) {
		out, _, _, err := e.FilterToolsList("echo", []byte(result))
		if err != nil {
			return
		}
		if _, _, changed, err := e.FilterToolsList("echo", out); err != nil || changed {
			t.Fatalf("filtered output still has a hidden tool or no longer parses: %s (%v)", out, err)
		}
	})
}
