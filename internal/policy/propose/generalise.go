package propose

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

var (
	// safeLiteral is a value Rover writes into a Cedar string literal:
	// printable ASCII without '"' and '\', at most 63 bytes.
	safeLiteral = regexp.MustCompile(`^[!#-\[\]-~]{1,63}$`)
	// safeHost is a normalised host (lower case, IDNs already punycode).
	safeHost = regexp.MustCompile(`^[a-z0-9._-]{1,253}$|^\[[0-9a-f:.]{2,45}\]$`)
	// identRE is a Cedar identifier (an argument or root name).
	identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	cedarReserved = map[string]bool{
		"true": true, "false": true, "if": true, "then": true, "else": true,
		"in": true, "is": true, "like": true, "has": true, "__cedar": true,
	}
	declaredArgs = func() map[string]bool {
		m := map[string]bool{}
		for _, a := range policy.DefaultArgNames {
			m[a] = true
		}
		return m
	}()
)

func defaultHome() (string, error) { return os.UserHomeDir() }

// resolved is p with symlinks resolved when it exists (macOS's /tmp is
// /private/tmp, and the normaliser compares resolved paths), else p.
func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// within reports whether p is dir or inside it, component by component.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pathValues returns a path argument's paths and whether it was a list.
func pathValues(a learn.Arg) ([]string, bool) {
	if a.Values != nil {
		return a.Values, true
	}
	return []string{a.Value}, false
}

// rootFor is the declared root containing every path (the deepest one), or "".
func (b *builder) rootFor(paths []string) string {
	best, bestLen := "", -1
	for _, r := range b.roots {
		inside := len(paths) > 0
		for _, p := range paths {
			inside = inside && (within(r.path, p) || within(r.resolved, p))
		}
		if inside && len(r.resolved) > bestLen {
			best, bestLen = r.name, len(r.resolved)
		}
	}
	return best
}

// partitionKey groups one tool's calls by argument names, path kinds and
// the declared root each path argument falls in, so calls under two roots
// become two rules instead of one rule whose directory climbs above both.
func (b *builder) partitionKey(o learn.Observation) string {
	names := make([]string, 0, len(o.Shape))
	for n := range o.Shape {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		a := o.Shape[n]
		sb.WriteString(n + ":" + a.Type)
		if a.Type == string(normalize.KindPath) {
			ps, list := pathValues(a)
			fmt.Fprintf(&sb, ":%v:%s", list, b.rootFor(ps))
		}
		sb.WriteByte(';')
	}
	return sb.String()
}

// normArgs are the arguments of a tool that a rule can constrain or that a
// normaliser maps (path, url, email kinds): from nc and from what was seen.
func (b *builder) normArgs(server, tool string, obs []learn.Observation) []string {
	set := map[string]bool{}
	for n, k := range b.nc.Servers[server][tool] {
		if k == normalize.KindPath || k == normalize.KindURL || k == normalize.KindEmail {
			set[n] = true
		}
	}
	for _, o := range obs {
		for n, a := range o.Shape {
			switch a.Type {
			case string(normalize.KindPath), string(normalize.KindURL), string(normalize.KindEmail):
				set[n] = true
			}
		}
	}
	return sortedSet(set)
}

// callDrafts generalises one tool's calls into one draft per partition. A
// tool that has a normaliser mapping or was seen with a path, url or email
// argument only gets constrained rules: a partition without a path or host
// condition is listed in the notes, not permitted.
func (b *builder) callDrafts(server, tool string, obs []learn.Observation) []draft {
	constrainable := len(b.nc.Servers[server][tool]) > 0 || len(b.normArgs(server, tool, obs)) > 0
	args := strings.Join(b.normArgs(server, tool, obs), " or ")
	parts := map[string][]learn.Observation{}
	var order []string
	for _, o := range obs {
		k := b.partitionKey(o)
		if _, ok := parts[k]; !ok {
			order = append(order, k)
		}
		parts[k] = append(parts[k], o)
	}
	sort.Strings(order)
	var out []draft
	for _, k := range order {
		d, err := b.callDraft(server, tool, parts[k])
		switch {
		case err != nil:
			b.note("%d %s/%s call(s) not proposed: %v", len(parts[k]), server, tool, err)
		case constrainable && !d.constrained:
			if args == "" {
				args = "a mapped argument"
			}
			b.note("%s/%s called %d time(s) without %s; write this rule by hand", server, tool, len(parts[k]), args)
		default:
			out = append(out, d)
		}
	}
	return out
}

// callDraft builds the rule for calls that share argument names and kinds.
func (b *builder) callDraft(server, tool string, obs []learn.Observation) (draft, error) {
	d := draft{server: server, tool: tool, action: learn.ActionCall, obs: obs}
	names := make([]string, 0, len(obs[0].Shape))
	for n := range obs[0].Shape {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		d.derived = []string{"called without arguments"}
		return d, nil
	}
	for _, n := range names {
		if err := b.argCond(&d, n, obs); err != nil {
			return draft{}, err
		}
	}
	return d, nil
}

// argCond adds the condition (or the reason there is none) for argument n.
func (b *builder) argCond(d *draft, n string, obs []learn.Observation) error {
	typ := obs[0].Shape[n].Type
	switch typ {
	case string(normalize.KindPath):
		return b.pathCond(d, n, obs)
	case string(normalize.KindURL):
		return hostCond(d, n, obs)
	case string(normalize.KindEmail), string(normalize.KindShellCommand), string(normalize.KindSQL):
		d.derived = append(d.derived, n+" not constrained (the schema has no context.norm type for "+typ+")")
	case "string":
		literalCond(d, n, obs)
	default:
		d.derived = append(d.derived, n+" not constrained ("+typ+")")
	}
	return nil
}

// pathCond: the deepest common directory, as a root.
func (b *builder) pathCond(d *draft, n string, obs []learn.Observation) error {
	if !identRE.MatchString(n) || cedarReserved[n] {
		return fmt.Errorf("argument name %q is not a Cedar identifier", n)
	}
	var all []string
	_, list := pathValues(obs[0].Shape[n])
	for _, o := range obs {
		ps, _ := pathValues(o.Shape[n])
		for _, p := range ps {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("argument %s held a relative path (no roots configured?)", n)
			}
		}
		all = append(all, ps...)
	}
	if list != policy.IsPluralPathArg(n) {
		return fmt.Errorf("argument %s was a %s, but the schema declares it as %s", n, plural(list), plural(!list))
	}
	root := b.rootFor(all)
	how := "inside root " + root + " = " + b.rootPath(root)
	if root == "" {
		dir := commonDir(all)
		if b.tooBroad(dir) {
			return fmt.Errorf("the paths of %s share only %s: too broad, write this rule by hand", n, dir)
		}
		root = b.suggestRoot(dir)
		how = fmt.Sprintf("inside %s, the deepest directory the %d path(s) share (new root %s = %s)", dir, len(all), root, dir)
	}
	attr := "under_" + root
	if list {
		attr = "all_under_" + root
	}
	d.conds = append(d.conds, fmt.Sprintf("context.norm has %s.%s && context.norm.%s.%s == true", n, attr, n, attr))
	d.constrained = true
	d.derived = append(d.derived, n+" "+how)
	switch {
	case n == "path" && !list:
		d.yamlWhen = append(d.yamlWhen, "path_under: "+root)
	case d.yamlNo == "":
		d.yamlNo = "YAML path_under only reads the argument named path, not " + n
	}
	return nil
}

func plural(list bool) string {
	if list {
		return "list of paths"
	}
	return "single path"
}

// hostCond: the set of hosts seen.
func hostCond(d *draft, n string, obs []learn.Observation) error {
	if !identRE.MatchString(n) || cedarReserved[n] {
		return fmt.Errorf("argument name %q is not a Cedar identifier", n)
	}
	hosts := map[string]bool{}
	for _, o := range obs {
		h := o.Shape[n].Value
		if !safeHost.MatchString(h) {
			return fmt.Errorf("argument %s had a host Rover will not write into Cedar", n)
		}
		hosts[h] = true
	}
	list := sortedSet(hosts)
	d.conds = append(d.conds, fmt.Sprintf("context.norm has %s && %s.contains(context.norm.%s.host)", n, cedarStringSet(list), n))
	d.constrained = true
	d.derived = append(d.derived, n+" host in "+strings.Join(list, ", "))
	switch {
	case n == "url":
		d.yamlWhen = append(d.yamlWhen, "host_in: "+jsonList(list))
	case d.yamlNo == "":
		d.yamlNo = "YAML host_in only reads the argument named url, not " + n
	}
	return nil
}

// literalCond: one short value, always the same, on a declared argument.
func literalCond(d *draft, n string, obs []learn.Observation) {
	vals := map[string]bool{}
	for _, o := range obs {
		v := o.Shape[n].Value
		if v == "" {
			d.derived = append(d.derived, n+" not constrained (its value is not recorded: only enum-like arguments with a plain, non-secret word are)")
			return
		}
		vals[v] = true
	}
	switch {
	case len(vals) > 1:
		d.derived = append(d.derived, fmt.Sprintf("%s not constrained (%d different values)", n, len(vals)))
	case !declaredArgs[n]:
		d.derived = append(d.derived, n+" not constrained (context.args."+n+" is not in the schema)")
	default:
		v := sortedSet(vals)[0]
		if !safeLiteral.MatchString(v) {
			d.derived = append(d.derived, n+" not constrained (its value has characters Rover will not write into Cedar)")
			return
		}
		d.conds = append(d.conds, fmt.Sprintf(`context.args has %s && context.args.%s == "%s"`, n, n, v))
		d.derived = append(d.derived, fmt.Sprintf("%s always %q", n, v))
		if d.yamlNo == "" {
			d.yamlNo = "context.args." + n + " == \"" + v + "\" has no YAML form"
		}
	}
}

// commonDir is the directory a path rule is derived from. One distinct
// path: the path itself when it is an existing directory now, else its
// parent. Several: the deepest directory containing all of them, taken
// over the paths themselves (component by component), so "/p" and
// "/p/a.txt" give "/p", not its parent.
func commonDir(paths []string) string {
	uniq := map[string]bool{}
	for _, p := range paths {
		uniq[filepath.Clean(p)] = true
	}
	list := sortedSet(uniq)
	if len(list) == 1 {
		p := list[0]
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
		return filepath.Dir(p)
	}
	sep := string(filepath.Separator)
	common := strings.Split(list[0], sep)
	for _, p := range list[1:] {
		parts := strings.Split(p, sep)
		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}
		common = common[:n]
	}
	dir := strings.Join(common, sep)
	if dir == "" {
		return sep
	}
	return dir
}

// tooBroad refuses "/", a top-level directory, and the home directory or
// anything above it: a root there would let the agent reach ~/.ssh.
func (b *builder) tooBroad(dir string) bool {
	if dir == string(filepath.Separator) || filepath.Dir(dir) == string(filepath.Separator) {
		return true
	}
	return slices.ContainsFunc(b.home, func(h string) bool { return within(dir, h) })
}

// suggestRoot names a new root after dir's last component. A root is
// shared only by rules whose directory is exactly the same: reusing a
// broader root suggested for another tool would widen this rule (found by
// independent verification of M6).
func (b *builder) suggestRoot(dir string) string {
	for _, r := range b.newRoots {
		if r.Path == dir {
			return r.Name
		}
	}
	base := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return '_'
	}, filepath.Base(dir))
	if base == "" || base[0] >= '0' && base[0] <= '9' || cedarReserved[base] {
		base = "r_" + base
	}
	name := base
	for n := 2; b.names[name]; n++ {
		name = fmt.Sprintf("%s_%d", base, n)
	}
	b.names[name] = true
	b.newRoots = append(b.newRoots, Root{Name: name, Path: dir})
	return name
}

// rootPath is the path of a declared root.
func (b *builder) rootPath(name string) string {
	for _, r := range b.roots {
		if r.name == name {
			return r.path
		}
	}
	return ""
}
