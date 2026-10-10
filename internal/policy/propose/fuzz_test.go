package propose

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// FuzzBuild: observations are built from names and values the agent and
// the server choose. Whatever they are, Build must not panic, and every
// proposal it returns must load against the schema roverd would build
// (and its YAML, when there is one, must compile).
func FuzzBuild(f *testing.F) {
	f.Add("files", "read_file", "path", byte(0), "/srv/x/a.txt", "/srv/x/sub/b.txt", false)
	f.Add("fetch", "fetch", "url", byte(1), "pkg.go.dev", "docs.python.org", false)
	f.Add("gh", "list", "branch", byte(2), "main", "main", true)
	f.Add("files", "read_many", "paths", byte(128), "/srv/p/a", "/srv/p/b", false)
	f.Add("s", `t"); permit (principal, action, resource);//`, "x y", byte(3), "/", "../..", false)
	f.Fuzz(func(t *testing.T, server, tool, arg string, kind byte, v1, v2 string, flag bool) {
		kinds := []string{"path", "url", "string", "email", "number"}
		typ := kinds[int(kind)%len(kinds)]
		mk := func(i int, v string) learn.Observation {
			a := learn.Arg{Type: typ, Value: v}
			if typ == "path" && kind >= 128 {
				a = learn.Arg{Type: typ, Values: []string{v1, v2}}
			}
			return learn.Observation{TS: t0.Add(time.Duration(i) * time.Minute), Server: server, Tool: tool, Action: learn.ActionCall,
				Shape: map[string]learn.Arg{arg: a}}
		}
		obs := []learn.Observation{
			mk(0, v1), mk(1, v2),
			{TS: t0, Server: server, Action: learn.ActionList},
			{TS: t0, Server: server, Action: learn.ActionRead, Shape: map[string]learn.Arg{"uri": {Type: "string", Value: v1}}},
			{TS: t0, Server: server, Tool: tool + "2", Action: learn.ActionCall},
		}
		if flag {
			obs[1].Flagged = []string{"instruction_phrase"}
		}
		nc := normalize.Config{}
		if k := normalize.Kind(typ); (k == normalize.KindPath || k == normalize.KindURL) && identRE.MatchString(arg) && !cedarReserved[arg] {
			nc.Servers = map[string]map[string]normalize.Rules{server: {tool: {arg: k}}}
		}

		p, err := Build(obs, nil, nil, nc)
		if err != nil {
			t.Fatal(err)
		}

		names := make([]string, 0, len(p.NewRoots))
		for _, r := range p.NewRoots {
			names = append(names, r.Name)
		}
		schema, err := policy.SchemaFor(policyfiles.Schema, policy.NewSchemaExtension(names, nc))
		if err != nil {
			t.Skip("schema for this normaliser config is invalid:", err)
		}
		if _, err := policy.Load(p.Cedar, "proposal.cedar", schema); err != nil {
			t.Fatalf("proposal does not load: %v\n%s", err, p.Cedar)
		}
		if len(p.YAML) > 0 {
			if _, err := yaml2cedar.Compile(p.YAML, "p.yaml"); err != nil {
				t.Fatalf("YAML does not compile: %v\n%s", err, p.YAML)
			}
		}
	})
}
