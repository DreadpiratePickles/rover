package yaml2cedar

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

var update = flag.Bool("update", false, "rewrite the golden .cedar files")

func goldenCases(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) != 6 {
		t.Fatalf("want 6 golden cases, found %d", len(files))
	}
	return files
}

func compileFile(t *testing.T, path string) Compiled {
	t.Helper()
	src, err := os.ReadFile(path) //nolint:gosec // G304: test data
	if err != nil {
		t.Fatal(err)
	}
	out, err := Compile(src, filepath.Base(path))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return out
}

func TestGolden(t *testing.T) {
	for _, path := range goldenCases(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			// Arrange
			golden := strings.TrimSuffix(path, ".yaml") + ".cedar"

			// Act
			got := compileFile(t, path).Cedar

			// Assert
			if *update {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden) //nolint:gosec // G304: test data
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s (run go test -update):\n%s", golden, got)
			}
		})
	}
}

func TestEveryGoldenPassesPolicyLoad(t *testing.T) {
	for _, path := range goldenCases(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			// Arrange
			c := compileFile(t, path)
			schema, err := policy.SchemaFor(policyfiles.Schema, policy.NewSchemaExtension(c.RootOrder, normalize.BuiltIn()))
			if err != nil {
				t.Fatal(err)
			}

			// Act
			eng, err := policy.Load(c.Cedar, filepath.Base(path), schema)

			// Assert
			if err != nil {
				t.Fatalf("policy.Load: %v\n%s", err, c.Cedar)
			}
			if got := len(eng.Policies()); got != len(c.Rules) {
				t.Errorf("%d policies loaded, %d rules compiled", got, len(c.Rules))
			}
			for i, p := range eng.Policies() {
				if p.ID != c.Rules[i].ID || p.Effect != c.Rules[i].Effect {
					t.Errorf("policy %d is %+v, rule is %+v", i, p, c.Rules[i])
				}
			}
		})
	}
}

func TestSpecExampleSettings(t *testing.T) {
	// Act
	c := compileFile(t, filepath.Join("testdata", "spec54.yaml"))

	// Assert
	if c.Mode != "enforce" {
		t.Errorf("mode %q", c.Mode)
	}
	if c.Roots["projects"] != "~/projects" || len(c.RootOrder) != 1 {
		t.Errorf("roots %v %v", c.Roots, c.RootOrder)
	}
	if got := c.Labels["filesystem"]["write_file"]; len(got) != 1 || got[0] != "destructive" {
		t.Errorf("labels %v", c.Labels)
	}
	want := []RuleInfo{
		{"fs-read-projects", 8, "permit", "filesystem", "read_file", false},
		{"gh-no-delete", 11, "forbid", "github", "delete_repository", false},
		{"gh-push-needs-approval", 14, "permit", "github", "push_files", false},
		{"trifecta", 17, "forbid", "*", "*", false},
		{"filesystem-list-tools", 8, "permit", "filesystem", "", true},
		{"github-list-tools", 14, "permit", "github", "", true},
	}
	if len(c.Rules) != len(want) {
		t.Fatalf("rules %+v", c.Rules)
	}
	for i := range want {
		if c.Rules[i] != want[i] {
			t.Errorf("rule %d: got %+v, want %+v", i, c.Rules[i], want[i])
		}
	}
}

const head = "version: 1\ndefaults: deny\n"

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		line, col int
		msg       string
	}{
		{"typo alow", head + "rules:\n  - id: a\n    alow: fs.read_file\n", 5, 5, `unknown key "alow"`},
		{"unknown top-level key", head + "rulez: []\n", 3, 1, `unknown key "rulez"`},
		{"unknown condition", head + "rules:\n  - id: a\n    allow: fs.read\n    when: { path_over: x }\n", 6, 13, `unknown key "path_over"`},
		{"undeclared root", head + "roots: { projects: ~/p }\nrules:\n  - id: a\n    allow: fs.read\n    when: { path_under: secrets }\n", 7, 25, `root "secrets" is not declared`},
		{"id injection", head + "rules:\n  - id: 'x\") ; permit(principal, action, resource); //'\n    allow: fs.read\n", 4, 9, "never escaped"},
		{"id with newline", head + "rules:\n  - id: \"a\\nb\"\n    allow: fs.read\n", 4, 9, "only letters"},
		{"duplicate id", head + "rules:\n  - id: a\n    allow: fs.read\n  - id: a\n    allow: fs.write\n", 6, 5, `already used on line 4`},
		{"missing id", head + "rules:\n  - allow: fs.read\n", 4, 5, "needs an id"},
		{"allow and deny", head + "rules:\n  - id: a\n    allow: fs.read\n    deny: fs.read\n", 6, 5, "exactly one of allow and deny"},
		{"neither allow nor deny", head + "rules:\n  - id: a\n", 4, 5, "needs allow"},
		{"bad server chars", head + "rules:\n  - id: a\n    allow: 'fs\"x.read'\n", 5, 12, "is not <server>.<tool>"},
		{"no tool", head + "rules:\n  - id: a\n    allow: filesystem\n", 5, 12, "is not <server>.<tool>"},
		{"allow star", head + "rules:\n  - id: a\n    allow: \"*\"\n", 5, 12, "would allow everything"},
		{"hide with when", head + "rules:\n  - id: a\n    deny: fs.write\n    when: { tool_label: egress }\n    hide: true\n", 7, 5, "cannot be combined with when"},
		{"hide on allow", head + "rules:\n  - id: a\n    allow: fs.read\n    hide: true\n", 6, 5, "only makes sense on a deny"},
		{"hide on star", head + "rules:\n  - id: a\n    deny: \"*\"\n    hide: true\n", 6, 5, "concrete"},
		{"require on deny", head + "rules:\n  - id: a\n    deny: fs.write\n    require: approval\n", 6, 5, "only makes sense on an allow"},
		{"require other", head + "rules:\n  - id: a\n    allow: fs.write\n    require: sudo\n", 6, 14, "only accepted value is approval"},
		{"unknown label in rule", head + "rules:\n  - id: a\n    deny: \"*\"\n    when: { tool_label: exfil }\n", 6, 25, `unknown label "exfil"`},
		{"unknown label in servers", head + "servers:\n  fs:\n    labels: { read: [secret] }\n", 5, 22, `unknown label "secret"`},
		{"unknown server key", head + "servers:\n  fs:\n    lables: {}\n", 5, 5, `unknown key "lables"`},
		{"hour wrap-around", head + "rules:\n  - id: a\n    allow: fs.read\n    when: { hour_between: [22, 6] }\n", 6, 27, "split the rule"},
		{"hour out of range", head + "rules:\n  - id: a\n    allow: fs.read\n    when: { hour_between: [0, 25] }\n", 6, 31, "want 1..24"},
		{"hour not a number", head + "rules:\n  - id: a\n    allow: fs.read\n    when: { hour_between: [nine, 17] }\n", 6, 28, "whole number"},
		{"host with scheme", head + "rules:\n  - id: a\n    allow: fetch.fetch\n    when: { host_in: [\"https://x.com\"] }\n", 6, 23, "lowercase ASCII host"},
		{"host uppercase", head + "rules:\n  - id: a\n    allow: fetch.fetch\n    when: { host_in: [Example.com] }\n", 6, 23, "lowercase ASCII host"},
		{"empty when", head + "rules:\n  - id: a\n    allow: fs.read\n    when: {}\n", 6, 11, "at least one condition"},
		{"session unknown key", head + "rules:\n  - id: a\n    deny: \"*\"\n    when: { session: { touched: true } }\n", 6, 24, `unknown key "touched"`},
		{"session not bool", head + "rules:\n  - id: a\n    deny: \"*\"\n    when: { session: { saw_untrusted: yes please } }\n", 6, 39, "true or false"},
		{"version 2", "version: 2\ndefaults: deny\n", 1, 10, "not supported"},
		{"missing version", "defaults: deny\n", 1, 1, "missing \"version: 1\""},
		{"defaults allow", "version: 1\ndefaults: allow\n", 2, 11, "only accepted value is deny"},
		{"missing defaults", "version: 1\n", 1, 1, "missing \"defaults: deny\""},
		{"bad mode", head + "mode: audit\n", 3, 7, "want observe or enforce"},
		{"root not identifier", head + "roots: { my-root: /x }\n", 3, 10, "Cedar identifier"},
		{"duplicate root", head + "roots:\n  a: /x\n  a: /y\n", 5, 3, "appears twice"},
		{"duplicate key", head + "mode: observe\nmode: enforce\n", 4, 1, "appears twice"},
		{"anchor", head + "roots: &r { a: /x }\n", 3, 8, "anchors and aliases"},
		{"two documents", head + "---\nversion: 1\n", 3, 0, "exactly one YAML document"},
		{"second document syntax error", head + "---\nrules: [\n", 3, 0, "exactly one YAML document"},
		{"second document after explicit start", "---\n" + head + "rules: []\n---\nrules: [\n", 5, 0, "exactly one YAML document"},
		{"server starting with -", head + "servers:\n  -fs:\n    labels: { read: [egress] }\n", 4, 3, "start with a letter, digit or _"},
		{"rule server starting with -", head + "rules:\n  - id: a\n    allow: -fs.read\n", 5, 12, "is not <server>.<tool>"},
		{"not a mapping", "- 1\n", 1, 1, "must be a mapping"},
		{"syntax error", head + "rules: [\n", 3, 0, "yaml:"},
		{"empty", "", 1, 0, "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Act
			_, err := Compile([]byte(c.src), "policy.yaml")

			// Assert
			var ce *CompileError
			if !errors.As(err, &ce) {
				t.Fatalf("want *CompileError, got %v", err)
			}
			if ce.Line != c.line || ce.Col != c.col {
				t.Errorf("position %d:%d, want %d:%d (%v)", ce.Line, ce.Col, c.line, c.col, err)
			}
			if !strings.Contains(ce.Msg, c.msg) {
				t.Errorf("message %q does not contain %q", ce.Msg, c.msg)
			}
			if !strings.HasPrefix(err.Error(), "policy.yaml:") {
				t.Errorf("error %q does not start with the file name", err)
			}
		})
	}
}

func TestFileNameCannotInjectCedar(t *testing.T) {
	// Arrange
	src := []byte(head + "rules:\n  - id: a\n    allow: fs.read\n")

	// Act
	c, err := Compile(src, "p.yaml\npermit (principal, action, resource);")

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(c.Cedar), "\n") {
		if strings.HasPrefix(line, "permit (principal, action, resource)") {
			t.Fatalf("file name escaped its comment:\n%s", c.Cedar)
		}
	}
}

func TestOversizedSourceIsRefused(t *testing.T) {
	// Act
	_, err := Compile(make([]byte, MaxSourceBytes+1), "big.yaml")

	// Assert
	var ce *CompileError
	if !errors.As(err, &ce) || !strings.Contains(ce.Msg, "limit") {
		t.Fatalf("got %v", err)
	}
}

func TestNoRulesCompilesToNoPolicies(t *testing.T) {
	// Act
	c, err := Compile([]byte(head), "p.yaml")

	// Assert
	if err != nil || len(c.Rules) != 0 || bytes.Contains(c.Cedar, []byte("permit (")) {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestStarterYAMLCompilesAndLoads(t *testing.T) {
	// Arrange
	c, err := Compile(policyfiles.StarterYAML, "policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := policy.SchemaFor(policyfiles.Schema, policy.NewSchemaExtension(c.RootOrder, normalize.BuiltIn()))
	if err != nil {
		t.Fatal(err)
	}

	// Act
	_, err = policy.Load(c.Cedar, "policy.yaml", schema)

	// Assert
	if err != nil || c.Mode != "observe" || len(c.Rules) != 6 {
		t.Fatalf("%v mode=%q rules=%d", err, c.Mode, len(c.Rules))
	}
}

func TestImpliedListToolsPermits(t *testing.T) {
	// Arrange
	src := head + `rules:
  - id: fs-read
    allow: fs.read_file
  - id: fs-write
    allow: fs.write_file
  - id: gh-no-delete
    deny: gh.delete_repository
`

	// Act
	c, err := Compile([]byte(src), "p.yaml")

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(c.Cedar, []byte(`@id("fs-list-tools")`)); n != 1 {
		t.Errorf("want exactly one fs-list-tools permit, got %d:\n%s", n, c.Cedar)
	}
	for _, want := range []string{
		"// implied: allow rules for fs need the agent to see the tool list\n",
		`permit (principal, action == Action::"list_tools", resource == Server::"fs");`,
	} {
		if !bytes.Contains(c.Cedar, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, c.Cedar)
		}
	}
	if bytes.Contains(c.Cedar, []byte("gh-list-tools")) || bytes.Contains(c.Cedar, []byte(`Server::"gh"`)) {
		t.Errorf("a deny-only server must get no list_tools permit:\n%s", c.Cedar)
	}
	last := c.Rules[len(c.Rules)-1]
	if !last.Implied || last.ID != "fs-list-tools" || last.Line != 4 {
		t.Errorf("implied rule info %+v", last)
	}
}

func TestImpliedListToolsIDCollision(t *testing.T) {
	// Arrange
	src := head + `rules:
  - id: fs-read
    allow: fs.read_file
  - id: fs-list-tools
    deny: fs.write_file
`

	// Act
	_, err := Compile([]byte(src), "p.yaml")

	// Assert
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CompileError, got %v", err)
	}
	if ce.Line != 6 || !strings.Contains(ce.Msg, "(line 6)") || !strings.Contains(ce.Msg, "line 4") {
		t.Fatalf("error must name both lines: %v", err)
	}
}
