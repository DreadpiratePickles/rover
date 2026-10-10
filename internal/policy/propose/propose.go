// Package propose turns learn-mode observations (internal/learn) into a
// proposed allow-list policy: `rover policy propose` (plan M6, D6).
//
// LESSON (M6): Rover's policy is an allow-list. Default deny means a
// block-list ("forbid what we know is bad") is never the base layer: the
// attacker only needs one thing we did not think of. An allow-list fails the
// other way, by blocking something legitimate we did not think of, and learn
// mode exists to make writing one cheap. It generalises what it saw:
//
//   - paths become the deepest directory they share, expressed as a root
//     (an existing one when the paths lie inside it, else a suggested one
//     for exactly that directory, never widened to fit another tool);
//   - URLs become their hosts;
//   - a short argument seen with exactly one value keeps that value;
//   - a tool with no normaliser mapping, never seen with a path, url or
//     e-mail argument, gets a plain permit; a tool that has a constrained
//     rule never gets an unconstrained one beside it (that would cancel
//     it); every server whose tools were listed gets a list_tools permit.
//
// What it never does: propose anything pinning or detection flagged (those
// calls are returned in Suspicious), propose a root at "/", at a top-level
// directory, or at or above the user's home (too broad: write that rule by
// hand), or embed a name or value in Cedar that would need escaping.
package propose

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Proposal is the result of Build.
type Proposal struct {
	Cedar []byte
	// YAML is the policy.yaml equivalent, or empty when some rule has no
	// YAML form; YAMLNote then says which.
	YAML     []byte
	YAMLNote string
	Rules    []ProposedRule
	// Suspicious are the flagged observations: never proposed.
	Suspicious []learn.Observation
	// NewRoots are roots the proposal uses that config.yaml does not
	// declare yet: add them before applying it.
	NewRoots []Root
	// Notes list calls that were seen but not proposed, and why.
	Notes []string
	// Used is the number of observations the rules were derived from.
	Used int
}

// ProposedRule is one rule of the proposal.
type ProposedRule struct {
	ID, Server, Tool string
	Action           string // learn.ActionCall, ActionList or ActionRead
	Derived          string // what it was derived from, in one sentence
	Calls            int
	First, Last      time.Time
	Cedar            string
	YAML             string // "" when the rule has no YAML form
}

// Root is a named directory.
type Root struct{ Name, Path string }

// Load reads the observations from roverd's state database (when roverd is
// not running; otherwise the CLI asks roverd with observations_dump).
func Load(db *state.DB) ([]learn.Observation, error) { return learn.Load(db) }

// homeDir is the user's home directory; a test may replace it.
var homeDir = defaultHome

// safeName is a server or tool name Rover will write into Cedar: nothing
// that needs escaping. Anything else is left for a human to write.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Build generalises obs. roots maps the declared root names to their
// (absolute, "~"-expanded) paths, as in config.yaml; labels are config.yaml's
// tool labels, carried into the YAML so applying it keeps them; nc is the
// normaliser config the observations were recorded with (a tool it maps can
// only get constrained rules).
func Build(obs []learn.Observation, roots map[string]string, labels map[string]map[string][]string, nc normalize.Config) (Proposal, error) {
	b := newBuilder(roots)
	b.nc = nc
	var p Proposal
	groups := map[groupKey][]learn.Observation{}
	dropped := 0
	for _, o := range obs {
		if len(o.Flagged) > 0 {
			p.Suspicious = append(p.Suspicious, o)
			continue
		}
		if o.DroppedArgs > 0 {
			dropped++ // its shape is incomplete: a rule from it could be too broad
			continue
		}
		k := groupKey{server: o.Server, action: o.Action, tool: o.Tool}
		groups[k] = append(groups[k], o)
		p.Used++
	}
	sort.SliceStable(p.Suspicious, func(i, j int) bool { return p.Suspicious[i].TS.Before(p.Suspicious[j].TS) })
	if dropped > 0 {
		b.note("%d call(s) not proposed: arguments were left out of their observation to bound its size", dropped)
	}
	for _, k := range sortedKeys(groups) {
		b.group(k, groups[k])
	}
	p.Rules, p.Notes, p.NewRoots = b.rules, b.notes, b.newRoots
	p.Cedar = renderCedar(p)
	p.YAML, p.YAMLNote = renderYAML(p, b, labels)
	return p, nil
}

// groupKey is one (server, action, tool).
type groupKey struct{ server, action, tool string }

var actionOrder = map[string]int{learn.ActionList: 0, learn.ActionCall: 1, learn.ActionRead: 2}

func sortedKeys(m map[groupKey][]learn.Observation) []groupKey {
	keys := make([]groupKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.server != b.server {
			return a.server < b.server
		}
		if actionOrder[a.action] != actionOrder[b.action] {
			return actionOrder[a.action] < actionOrder[b.action]
		}
		return a.tool < b.tool
	})
	return keys
}

// builder accumulates rules, notes and suggested roots.
type builder struct {
	roots    []declaredRoot
	rules    []ProposedRule
	notes    []string
	newRoots []Root
	ids      map[string]bool
	names    map[string]bool // root names in use (declared and suggested)
	home     []string        // the home directory, as written and resolved
	yamlOK   map[string]bool // server -> has a call rule with a YAML form
	yamlWhy  string          // the first rule without a YAML form
	yamlBody []yamlRule
	nc       normalize.Config
}

type declaredRoot struct{ name, path, resolved string }

func newBuilder(roots map[string]string) *builder {
	b := &builder{ids: map[string]bool{}, names: map[string]bool{}, yamlOK: map[string]bool{}}
	names := make([]string, 0, len(roots))
	for n := range roots {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.roots = append(b.roots, declaredRoot{n, roots[n], resolved(roots[n])})
		b.names[n] = true
	}
	if h, err := homeDir(); err == nil && h != "" {
		b.home = []string{filepath.Clean(h), resolved(h)}
	}
	return b
}

func (b *builder) note(format string, a ...any) {
	b.notes = append(b.notes, fmt.Sprintf(format, a...))
}

// group turns one (server, action, tool) into rules.
func (b *builder) group(k groupKey, obs []learn.Observation) {
	label := k.server + "/" + k.tool
	if k.action != learn.ActionCall {
		label = k.server + " " + k.action
	}
	if !safeName.MatchString(k.server) || (k.action == learn.ActionCall && !safeName.MatchString(k.tool)) {
		b.note("%d %s call(s) not proposed: the server or tool name has characters Rover will not write into Cedar; write this rule by hand", len(obs), quoteSafe(label))
		return
	}
	switch k.action {
	case learn.ActionList:
		b.add(draft{server: k.server, tool: "list-tools", action: k.action, obs: obs, derived: []string{"the agent listed the tools of " + k.server}})
	case learn.ActionRead:
		b.readRule(k.server, obs)
	case learn.ActionCall:
		for _, d := range b.callDrafts(k.server, k.tool, obs) {
			b.add(d)
		}
	default:
		b.note("%d %s observation(s) not proposed: unknown action", len(obs), quoteSafe(label))
	}
}

// draft is a rule before it gets its id and text.
type draft struct {
	server, tool, action string
	obs                  []learn.Observation
	conds                []string // Cedar boolean expressions, ANDed
	derived              []string
	resourceIn           bool     // read_resource: resource in Server
	yamlWhen             []string // YAML when: entries; nil with yamlNo set
	constrained          bool     // has a path or host condition
	yamlNo               string   // why this rule has no YAML form
}

// add assigns an id and renders the rule.
func (b *builder) add(d draft) {
	base := "learned-" + d.server + "-" + d.tool
	if len(base) > 120 {
		base = base[:120]
	}
	id := base
	for n := 2; b.ids[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	b.ids[id] = true
	first, last := span(d.obs)
	r := ProposedRule{
		ID: id, Server: d.server, Action: d.action, Calls: len(d.obs), First: first, Last: last,
		Derived: strings.Join(d.derived, "; "),
	}
	if d.action == learn.ActionCall {
		r.Tool = d.tool
	}
	r.Cedar = cedarRule(r, d)
	r.YAML = b.yamlRule(r, d)
	b.rules = append(b.rules, r)
}

func span(obs []learn.Observation) (first, last time.Time) {
	for i, o := range obs {
		if i == 0 || o.TS.Before(first) {
			first = o.TS
		}
		if i == 0 || o.TS.After(last) {
			last = o.TS
		}
	}
	return first.UTC(), last.UTC()
}

// readRule permits read_resource of the URIs seen on server.
func (b *builder) readRule(server string, obs []learn.Observation) {
	uris := map[string]bool{}
	for _, o := range obs {
		u := o.Shape["uri"].Value
		if !safeLiteral.MatchString(u) {
			b.note("%d resources/read call(s) on %s not proposed: a URI was too long, had white space or characters Rover will not write into Cedar; write this rule by hand", len(obs), server)
			return
		}
		uris[u] = true
	}
	list := sortedSet(uris)
	b.add(draft{
		server: server, tool: "read-resource", action: learn.ActionRead, obs: obs, resourceIn: true,
		conds:   []string{cedarStringSet(list) + ".contains(resource.uri)"},
		derived: []string{"resources/read of " + strings.Join(list, ", ")},
		yamlNo:  "YAML has no read_resource rule",
	})
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// quoteSafe makes attacker-supplied text safe for a note on a terminal.
func quoteSafe(s string) string {
	return strings.Trim(fmt.Sprintf("%q", s), `"`)
}
