package propose

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

var t0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func init() { homeDir = func() (string, error) { return "/home/me", nil } }

func callObs(i int, server, tool string, shape map[string]learn.Arg, flags ...string) learn.Observation {
	return learn.Observation{TS: t0.Add(time.Duration(i) * time.Minute), Client: "agent", Server: server, Tool: tool,
		Action: learn.ActionCall, Shape: shape, Flagged: flags}
}

func path(p string) map[string]learn.Arg {
	return map[string]learn.Arg{"path": {Type: "path", Value: p}}
}

// normalizers is the normaliser config the observations came from; the
// schema the proposal is validated against is generated from it.
const normalizers = `servers:
  files:
    read_file: {path: path}
    list_directory: {path: path}
    copy_to: {source: path}
    read_many: {paths: path}
    copy: {source: path}
  fetch:
    fetch: {url: url}
`

// mustLoad validates the proposal against the schema roverd would build
// for roots (declared plus suggested).
func mustLoad(t *testing.T, p Proposal, roots map[string]string) *policy.Engine {
	t.Helper()
	nc, err := normalize.Parse([]byte(normalizers))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range roots {
		names = append(names, n)
	}
	for _, r := range p.NewRoots {
		names = append(names, r.Name)
	}
	schema, err := policy.SchemaFor(policyfiles.Schema, policy.NewSchemaExtension(names, nc))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.Load(p.Cedar, "proposal.cedar", schema)
	if err != nil {
		t.Fatalf("proposal does not load: %v\n%s", err, p.Cedar)
	}
	return eng
}

func testNormalizers(t *testing.T) normalize.Config {
	t.Helper()
	nc, err := normalize.Parse([]byte(normalizers))
	if err != nil {
		t.Fatal(err)
	}
	return nc
}

func build(t *testing.T, obs []learn.Observation, roots map[string]string) Proposal {
	t.Helper()
	p, err := Build(obs, roots, nil, testNormalizers(t))
	if err != nil {
		t.Fatal(err)
	}
	mustLoad(t, p, roots)
	return p
}

func TestBuildSuggestsRootAtDeepestCommonDirectory(t *testing.T) {
	// Arrange
	obs := []learn.Observation{
		callObs(0, "files", "read_file", path("/srv/x/projects/a.txt")),
		callObs(5, "files", "read_file", path("/srv/x/projects/sub/b.txt")),
		{TS: t0, Server: "files", Action: learn.ActionList},
	}

	// Act
	p := build(t, obs, nil)

	// Assert
	if len(p.NewRoots) != 1 || p.NewRoots[0] != (Root{Name: "projects", Path: "/srv/x/projects"}) {
		t.Fatalf("new roots %+v", p.NewRoots)
	}
	cedar := string(p.Cedar)
	for _, want := range []string{
		`@id("learned-files-read_file")`,
		"// derived from 2 calls between 2026-10-01T09:00:00Z and 2026-10-01T09:05:00Z: path inside /srv/x/projects",
		`context.norm has path.under_projects && context.norm.path.under_projects == true`,
		`@id("learned-files-list-tools")`,
		`permit (principal, action == Action::"list_tools", resource == Server::"files");`,
	} {
		if !strings.Contains(cedar, want) {
			t.Errorf("Cedar lacks %q:\n%s", want, cedar)
		}
	}
	if strings.Contains(cedar, "a.txt") {
		t.Errorf("a single file must not leak into the rule:\n%s", cedar)
	}
}

func TestBuildUsesDeclaredRootAndSplitsAcrossRoots(t *testing.T) {
	roots := map[string]string{"work": "/srv/work", "notes": "/srv/notes"}
	obs := []learn.Observation{
		callObs(0, "files", "read_file", path("/srv/work/deep/a.txt")),
		callObs(1, "files", "read_file", path("/srv/notes/b.txt")),
	}
	p := build(t, obs, roots)
	cedar := string(p.Cedar)
	if len(p.NewRoots) != 0 || len(p.Rules) != 2 {
		t.Fatalf("new roots %+v, %d rules:\n%s", p.NewRoots, len(p.Rules), cedar)
	}
	for _, want := range []string{`@id("learned-files-read_file")`, `@id("learned-files-read_file-2")`, "path.under_work", "path.under_notes"} {
		if !strings.Contains(cedar, want) {
			t.Errorf("Cedar lacks %q:\n%s", want, cedar)
		}
	}
}

func TestBuildRefusesTooBroadRoot(t *testing.T) {
	for name, paths := range map[string][]string{
		"slash":     {"/etc/passwd", "/srv/x/a"},
		"top level": {"/srv/a/x", "/srv/b/y"},
		"home":      {"/home/me/projects/a", "/home/me/.ssh/id_rsa"},
	} {
		t.Run(name, func(t *testing.T) {
			obs := []learn.Observation{callObs(0, "files", "read_file", path(paths[0])), callObs(1, "files", "read_file", path(paths[1]))}
			p := build(t, obs, nil)
			if len(p.Rules) != 0 || len(p.NewRoots) != 0 || len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "too broad, write this rule by hand") {
				t.Fatalf("rules %d roots %+v notes %q", len(p.Rules), p.NewRoots, p.Notes)
			}
		})
	}
}

func TestBuildHostsEnumsAndPlainPermits(t *testing.T) {
	// Arrange
	obs := []learn.Observation{
		callObs(0, "fetch", "fetch", map[string]learn.Arg{"url": {Type: "url", Value: "pkg.go.dev"}}),
		callObs(1, "fetch", "fetch", map[string]learn.Arg{"url": {Type: "url", Value: "docs.python.org"}}),
		callObs(2, "gh", "list_issues", map[string]learn.Arg{"owner": {Type: "string", Value: "bobby"}, "n": {Type: "number"}}),
		callObs(3, "gh", "list_issues", map[string]learn.Arg{"owner": {Type: "string", Value: "bobby"}, "n": {Type: "number"}}),
		callObs(4, "gh", "search", map[string]learn.Arg{"query": {Type: "string", Value: "a"}}),
		callObs(5, "gh", "search", map[string]learn.Arg{"query": {Type: "string", Value: "b"}}),
		callObs(6, "gh", "whoami", nil),
	}

	// Act
	p := build(t, obs, nil)

	// Assert
	cedar := string(p.Cedar)
	for _, want := range []string{
		`context.norm has url && ["docs.python.org", "pkg.go.dev"].contains(context.norm.url.host)`,
		`context.args has owner && context.args.owner == "bobby"`,
		"n not constrained (number); owner always \"bobby\"",
		"query not constrained (2 different values)",
		"called without arguments",
		`resource == Tool::"gh/whoami"` + "\n);",
	} {
		if !strings.Contains(cedar, want) {
			t.Errorf("Cedar lacks %q:\n%s", want, cedar)
		}
	}
	if len(p.YAML) != 0 || !strings.Contains(p.YAMLNote, `learned-gh-list_issues: context.args.owner == "bobby" has no YAML form`) {
		t.Fatalf("an equality on context.args has no YAML form; note %q", p.YAMLNote)
	}
}

func TestBuildExcludesFlaggedObservations(t *testing.T) {
	obs := []learn.Observation{
		callObs(0, "files", "read_file", path("/srv/x/projects/a.txt")),
		callObs(1, "files", "read_file", path("/srv/x/loot/poison.txt"), "instruction_phrase"),
		callObs(2, "files", "delete_all", nil, learn.FlagPinMismatch),
	}
	p := build(t, obs, nil)
	if len(p.Suspicious) != 2 || p.Used != 1 || p.Suspicious[0].Tool != "read_file" {
		t.Fatalf("suspicious %+v used %d", p.Suspicious, p.Used)
	}
	cedar := string(p.Cedar)
	if strings.Contains(cedar, "loot") || strings.Contains(cedar, "delete_all") || !strings.Contains(cedar, "/srv/x/projects") {
		t.Fatalf("a flagged call reached the proposal:\n%s", cedar)
	}
}

func TestBuildYAMLEquivalent(t *testing.T) {
	// Arrange
	roots := map[string]string{"work": "/srv/work"}
	obs := []learn.Observation{
		{TS: t0, Server: "files", Action: learn.ActionList},
		callObs(0, "files", "read_file", path("/srv/work/a")),
		callObs(1, "files", "read_file", path("/srv/x/projects/b")),
		callObs(2, "fetch", "fetch", map[string]learn.Arg{"url": {Type: "url", Value: "pkg.go.dev"}}),
	}
	labels := map[string]map[string][]string{"fetch": {"fetch": {"egress"}}}

	// Act
	p, err := Build(obs, roots, labels, testNormalizers(t))
	if err != nil {
		t.Fatal(err)
	}

	// Assert: the YAML compiles and says the same thing.
	c, err := yaml2cedar.Compile(p.YAML, "p.yaml")
	if err != nil {
		t.Fatalf("YAML: %v (note %q)\n%s", err, p.YAMLNote, p.YAML)
	}
	y := string(p.YAML)
	for _, want := range []string{"path_under: work", "path_under: projects", `host_in: ["pkg.go.dev"]`, `projects: "/srv/x/projects"`, `"fetch": ["egress"]`} {
		if !strings.Contains(y, want) {
			t.Errorf("YAML lacks %q:\n%s", want, y)
		}
	}
	if c.Mode != "enforce" || c.Labels["fetch"]["fetch"][0] != "egress" || c.Roots["projects"] != "/srv/x/projects" {
		t.Fatalf("compiled: %+v %+v", c.Labels, c.Roots)
	}
	for _, r := range p.Rules {
		if r.Action == learn.ActionCall && r.YAML == "" {
			t.Errorf("rule %s has no YAML", r.ID)
		}
	}
}

func TestBuildNoYAMLForListOnlyServerOrOtherArgNames(t *testing.T) {
	for name, obs := range map[string][]learn.Observation{
		"list only":      {{TS: t0, Server: "quiet", Action: learn.ActionList}},
		"not named path": {callObs(0, "files", "copy", map[string]learn.Arg{"source": {Type: "path", Value: "/srv/x/p/a"}})},
	} {
		t.Run(name, func(t *testing.T) {
			p := build(t, obs, nil)
			if len(p.YAML) != 0 || !strings.HasPrefix(p.YAMLNote, "no YAML equivalent: learned-") {
				t.Fatalf("YAML %q note %q", p.YAML, p.YAMLNote)
			}
		})
	}
}

func TestBuildRefusesUnsafeNamesAndValues(t *testing.T) {
	obs := []learn.Observation{
		callObs(0, "files", `x"); permit (principal, action, resource);//`, nil),
		callObs(1, "gh", "get", map[string]learn.Arg{"owner": {Type: "string", Value: `a"b`}}),
		{TS: t0, Server: "docs", Action: learn.ActionRead, Shape: map[string]learn.Arg{"uri": {Type: "string"}}},
	}
	p := build(t, obs, nil)
	cedar := string(p.Cedar)
	if strings.Contains(cedar, "permit (principal, action, resource)") || strings.Contains(cedar, `a"b`) || strings.Contains(cedar, "read_resource") {
		t.Fatalf("unsafe text reached Cedar:\n%s", cedar)
	}
	if len(p.Notes) != 2 {
		t.Fatalf("notes %q", p.Notes)
	}
}

func TestBuildPathListsUseAllUnder(t *testing.T) {
	obs := []learn.Observation{callObs(0, "files", "read_many", map[string]learn.Arg{"paths": {Type: "path", Values: []string{"/srv/x/p/a", "/srv/x/p/q/b"}}})}
	p := build(t, obs, nil)
	if !strings.Contains(string(p.Cedar), "context.norm has paths.all_under_p && context.norm.paths.all_under_p == true") {
		t.Fatalf("%s", p.Cedar)
	}
}

func TestUnifiedDiff(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
	b := "1\n2\nthree\n4\n5\n6\n7\n8\n9\n10\n11\n"
	got := UnifiedDiff("cur", "next", []byte(a), []byte(b))
	want := "--- cur\n+++ next\n@@ -1,6 +1,6 @@\n 1\n 2\n-3\n+three\n 4\n 5\n 6\n@@ -8,3 +8,4 @@\n 8\n 9\n 10\n+11\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if UnifiedDiff("a", "b", []byte(a), []byte(a)) != "" {
		t.Fatal("equal inputs must give no diff")
	}
	if got := UnifiedDiff("a", "b", nil, []byte("x\n")); got != "--- a\n+++ b\n@@ -0,0 +1,1 @@\n+x\n" {
		t.Fatalf("from empty: %q", got)
	}
}

// H1 (independent verification): a root suggested for one tool must never
// widen another tool's rule. A directory given to one tool and files under
// it given to another share the root only because the directories are
// identical; nothing climbs to the parent.
func TestBuildRootsNeverWidenAcrossTools(t *testing.T) {
	// Arrange: real directories, because a single observed path that is a
	// directory is its own root.
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"projects/sub", "other"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	proj := filepath.Join(w, "projects")
	obs := []learn.Observation{
		callObs(0, "files", "list_directory", path(proj)),
		callObs(1, "files", "read_file", path(filepath.Join(proj, "a.txt"))),
		callObs(2, "files", "read_file", path(filepath.Join(proj, "sub", "b.txt"))),
	}

	// Act
	p := build(t, obs, nil)

	// Assert
	if len(p.NewRoots) != 1 || p.NewRoots[0] != (Root{Name: "projects", Path: proj}) {
		t.Fatalf("new roots %+v, want only projects = %s\n%s", p.NewRoots, proj, p.Cedar)
	}
	if !strings.Contains(string(p.Cedar), "(new root projects = "+proj+")") {
		t.Errorf("the comment must name the exact directory:\n%s", p.Cedar)
	}
	eng := mustLoad(t, p, nil)
	roots := []normalize.Root{{Name: "projects", Path: proj}}
	for target, want := range map[string]string{
		filepath.Join(proj, "a.txt"):          ipc.ActionForward,
		filepath.Join(proj, "sub", "new.txt"): ipc.ActionForward,
		filepath.Join(w, "other", "c.txt"):    ipc.ActionBlock,
		filepath.Join(w, "c.txt"):             ipc.ActionBlock,
	} {
		msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":` + strconv.Quote(target) + `}}}`
		o := eng.Decide(policy.Input{Mode: policy.ModeEnforce, Server: "files", Dir: policy.DirC2S, Msg: jsonrpc.Parse([]byte(msg)),
			Now: t0, Roots: roots, Normalizers: normalize.Rules{"path": normalize.KindPath}})
		if o.Action != want {
			t.Errorf("read_file %s: %s (%s), want %s", target, o.Action, o.Reason, want)
		}
	}
}

func TestCommonDirectory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		paths []string
		want  string
	}{
		"one existing directory": {[]string{dir}, dir},
		"one file":               {[]string{"/srv/p/a.txt"}, "/srv/p"},
		"same file twice":        {[]string{"/srv/p/a.txt", "/srv/p/a.txt"}, "/srv/p"},
		"two files, one dir":     {[]string{"/srv/p/a.txt", "/srv/p/b.txt"}, "/srv/p"},
		"file and subdir file":   {[]string{"/srv/p/a.txt", "/srv/p/sub/b.txt"}, "/srv/p"},
		"a path and its child":   {[]string{"/srv/p", "/srv/p/a.txt"}, "/srv/p"},
		"name prefix only":       {[]string{"/srv/p/ab", "/srv/p/abc"}, "/srv/p"},
	} {
		if got := commonDir(tc.paths); got != tc.want {
			t.Errorf("%s: commonDir(%q) = %s, want %s", name, tc.paths, got, tc.want)
		}
	}
}

// M1: once a tool has a constrained rule, calls without the constrained
// argument are not proposed (a plain permit would cancel the constraint).
func TestBuildNoPlainPermitBesideConstrainedRule(t *testing.T) {
	obs := []learn.Observation{
		callObs(0, "files", "read_file", path("/srv/x/p/a.txt")),
		callObs(1, "files", "read_file", nil),
		callObs(2, "files", "read_file", map[string]learn.Arg{"mode": {Type: "string", Value: "ro"}}),
	}
	p := build(t, obs, nil)
	if len(p.Rules) != 1 || !strings.Contains(p.Rules[0].Cedar, "under_p") {
		t.Fatalf("rules %+v", p.Rules)
	}
	if len(p.Notes) != 1 || p.Notes[0] != "files/read_file called 2 time(s) without path; write this rule by hand" {
		t.Fatalf("notes %q", p.Notes)
	}
}

// M1: a plain permit only for a tool with no normaliser mapping that was
// never seen with a path, url or email argument.
func TestBuildPlainPermitOnlyForUnmappedTools(t *testing.T) {
	obs := []learn.Observation{
		callObs(0, "files", "list_directory", nil), // mapped tool, called with {}
		callObs(1, "gh", "whoami", nil),            // unmapped, no arguments
		callObs(2, "mail", "send", map[string]learn.Arg{"to": {Type: "email", Value: "example.org"}}),
	}
	p := build(t, obs, nil)
	if len(p.Rules) != 1 || p.Rules[0].ID != "learned-gh-whoami" {
		t.Fatalf("rules %+v notes %q", p.Rules, p.Notes)
	}
	if len(p.Notes) != 2 {
		t.Fatalf("notes %q", p.Notes)
	}
}

func TestBuildSkipsObservationsWithDroppedArgs(t *testing.T) {
	o := callObs(0, "gh", "whoami", nil)
	o.DroppedArgs = 3
	p := build(t, []learn.Observation{o}, nil)
	if len(p.Rules) != 0 || len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "bound its size") {
		t.Fatalf("rules %+v notes %q", p.Rules, p.Notes)
	}
}

// resources/read is never proposed: URIs are not recorded. One honest note
// per server, with the count.
func TestBuildNeverProposesResourceReads(t *testing.T) {
	read := func(server string) learn.Observation {
		return learn.Observation{TS: t0, Server: server, Action: learn.ActionRead, Shape: map[string]learn.Arg{"uri": {Type: "string"}}}
	}
	p := build(t, []learn.Observation{read("docs"), read("docs"), read("wiki")}, nil)
	if len(p.Rules) != 0 || strings.Contains(string(p.Cedar), "read_resource") {
		t.Fatalf("rules %+v", p.Rules)
	}
	want := []string{
		"docs: resources/read is not proposed: URIs are not recorded (they can carry secrets); write this rule by hand (2 call(s))",
		"wiki: resources/read is not proposed: URIs are not recorded (they can carry secrets); write this rule by hand (1 call(s))",
	}
	if strings.Join(p.Notes, "|") != strings.Join(want, "|") {
		t.Fatalf("notes %q", p.Notes)
	}
}
