package yaml2cedar

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// rule is one checked entry of rules:.
type rule struct {
	id       string
	line     int
	allow    bool   // allow -> permit, deny -> forbid
	server   string // "*" for deny: "*"
	tool     string
	conds    []cond // ANDed, in YAML order
	approval bool   // require: approval
	hide     bool   // hide: true
	// implied marks the list_tools permit the compiler adds for a server
	// that has allow rules (see impliedListTools).
	implied bool
}

func (r rule) effect() string {
	if r.allow {
		return "permit"
	}
	return "forbid"
}

// callOnly reports whether the rule can only apply to tool calls: it names
// a tool, or one of its conditions reads tool-call data.
func (r rule) callOnly() bool {
	if r.server != "*" {
		return true
	}
	for _, c := range r.conds {
		if c.callOnly {
			return true
		}
	}
	return false
}

// cond is one condition already rendered as a Cedar boolean expression.
// callOnly is set when the expression reads context.norm or
// resource.labels, which exist only for Action::"call_tool".
type cond struct {
	cedar    string
	callOnly bool
}

func (c compiler) rules(n *yaml.Node, roots map[string]string) ([]rule, error) {
	if isNull(n) {
		return nil, nil
	}
	items, err := c.sequence(n, "rules")
	if err != nil {
		return nil, err
	}
	ids := map[string]int{}
	out := make([]rule, 0, len(items))
	for _, it := range items {
		r, err := c.rule(it, roots)
		if err != nil {
			return nil, err
		}
		if prev, dup := ids[r.id]; dup {
			return nil, c.errAt(it, "rule id %q is already used on line %d", r.id, prev)
		}
		ids[r.id] = r.line
		out = append(out, r)
	}
	return c.impliedListTools(out, items)
}

// impliedListTools appends one list_tools permit per server that has at
// least one allow rule, in order of each server's first allow. An allow rule
// is useless if the agent cannot see the tool in tools/list, and YAML has no
// syntax of its own for list_tools. A server with only deny rules gets
// nothing. A user rule whose id equals an implied id is an error: two
// policies must never share an id, and silently renaming either would make
// the audit log point at the wrong rule.
func (c compiler) impliedListTools(rules []rule, nodes []*yaml.Node) ([]rule, error) {
	byID := map[string]int{}
	for i, r := range rules {
		byID[r.id] = i
	}
	seen := map[string]bool{}
	out := rules
	for _, r := range rules {
		if !r.allow || seen[r.server] {
			continue
		}
		seen[r.server] = true
		id := r.server + "-list-tools"
		if i, clash := byID[id]; clash {
			return nil, c.errAt(nodes[i], "rule id %q (line %d) collides with the implied list_tools permit for server %q, "+
				"which the allow rule on line %d creates; rename the rule", id, rules[i].line, r.server, r.line)
		}
		out = append(out, rule{id: id, line: r.line, allow: true, server: r.server, implied: true})
	}
	return out, nil
}

// rule checks one rule mapping.
func (c compiler) rule(n *yaml.Node, roots map[string]string) (rule, error) {
	fields, err := c.mapping(n, "a rule", "id", "allow", "deny", "when", "require", "hide")
	if err != nil {
		return rule{}, err
	}
	r := rule{line: n.Line}
	var target, when, require, hide *yaml.Node
	for _, f := range fields {
		switch f.key.Value {
		case "id":
			if r.id, err = c.ruleID(f.val); err != nil {
				return rule{}, err
			}
		case "allow", "deny":
			if target != nil {
				return rule{}, c.errAt(f.key, "a rule has exactly one of allow and deny")
			}
			target, r.allow = f.val, f.key.Value == "allow"
		case "when":
			when = f.val
		case "require":
			require = f.key
		case "hide":
			hide = f.key
		}
	}
	if r.id == "" {
		return rule{}, c.errAt(n, "a rule needs an id")
	}
	if target == nil {
		return rule{}, c.errAt(n, "rule %s needs allow: <server>.<tool> or deny: <server>.<tool> | \"*\"", r.id)
	}
	if r.server, r.tool, err = c.target(target, r.allow); err != nil {
		return rule{}, err
	}
	if when != nil {
		if r.conds, err = c.when(when, roots); err != nil {
			return rule{}, err
		}
	}
	if err := c.requireApproval(&r, fields, require); err != nil {
		return rule{}, err
	}
	if err := c.hideTool(&r, fields, hide, when); err != nil {
		return rule{}, err
	}
	return r, nil
}

func (c compiler) ruleID(n *yaml.Node) (string, error) {
	id, err := c.str(n, "id")
	if err != nil {
		return "", err
	}
	if !ruleIDRE.MatchString(id) {
		return "", c.errAt(n, "rule id %q: only letters, digits, _, . and - are allowed (at most 128, not starting with . or -); ids are restricted, never escaped", id)
	}
	return id, nil
}

// target reads allow/deny: <server>.<tool>, or "*" for deny.
func (c compiler) target(n *yaml.Node, allow bool) (server, tool string, err error) {
	s, err := c.str(n, "allow/deny")
	if err != nil {
		return "", "", err
	}
	if s == "*" {
		if allow {
			return "", "", c.errAt(n, "allow: \"*\" would allow everything; name one <server>.<tool> per allow rule")
		}
		return "*", "*", nil
	}
	server, tool, ok := strings.Cut(s, ".")
	if !ok || !serverRE.MatchString(server) || !toolRE.MatchString(tool) || tool == "*" {
		return "", "", c.errAt(n, "%q is not <server>.<tool> (server: letters, digits, _ and -; tool: also .)", s)
	}
	return server, tool, nil
}

func (c compiler) requireApproval(r *rule, fields []field, require *yaml.Node) error {
	if require == nil {
		return nil
	}
	val := valueOf(fields, require)
	v, err := c.str(val, "require")
	if err != nil {
		return err
	}
	if v != "approval" {
		return c.errAt(val, "require %q: the only accepted value is approval", v)
	}
	if !r.allow {
		return c.errAt(require, "require: approval only makes sense on an allow rule (a deny is never approved)")
	}
	r.approval = true
	return nil
}

func (c compiler) hideTool(r *rule, fields []field, hide, when *yaml.Node) error {
	if hide == nil {
		return nil
	}
	v, err := c.boolean(valueOf(fields, hide), "hide")
	if err != nil {
		return err
	}
	switch {
	case !v:
		return nil
	case r.allow:
		return c.errAt(hide, "hide: true only makes sense on a deny rule")
	case when != nil:
		return c.errAt(hide, "hide: true cannot be combined with when: a hidden tool is removed from tools/list, which cannot know the call's conditions")
	case r.server == "*":
		return c.errAt(hide, "hide: true needs one concrete <server>.<tool>, not \"*\"")
	}
	r.hide = true
	return nil
}

func valueOf(fields []field, key *yaml.Node) *yaml.Node {
	for _, f := range fields {
		if f.key == key {
			return f.val
		}
	}
	return key
}

// when reads the conditions of a rule. Every key has one fixed Cedar
// mapping; the conditions are ANDed in YAML order.
func (c compiler) when(n *yaml.Node, roots map[string]string) ([]cond, error) {
	fields, err := c.mapping(n, "when", "path_under", "session", "tool_label", "hour_between", "host_in")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, c.errAt(n, "when: needs at least one condition (leave when out instead)")
	}
	out := make([]cond, 0, len(fields))
	for _, f := range fields {
		var cs []cond
		switch f.key.Value {
		case "path_under":
			cs, err = c.pathUnder(f.val, roots)
		case "session":
			cs, err = c.session(f.val)
		case "tool_label":
			cs, err = c.toolLabel(f.val)
		case "hour_between":
			cs, err = c.hourBetween(f.val)
		case "host_in":
			cs, err = c.hostIn(f.val)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	return out, nil
}

// pathUnder: path_under: <root> -> the normalised "path" argument is inside
// the root. The `has` guard makes a call without a path argument a plain
// false (no evaluation error).
func (c compiler) pathUnder(n *yaml.Node, roots map[string]string) ([]cond, error) {
	root, err := c.str(n, "path_under")
	if err != nil {
		return nil, err
	}
	if _, ok := roots[root]; !ok {
		return nil, c.errAt(n, "path_under: root %q is not declared under roots:", root)
	}
	attr := "under_" + root
	return []cond{{
		cedar:    "context.norm has path." + attr + " && context.norm.path." + attr + " == true",
		callOnly: true,
	}}, nil
}

// session: {touched_private: bool, saw_untrusted: bool}.
func (c compiler) session(n *yaml.Node) ([]cond, error) {
	fields, err := c.mapping(n, "when.session", "touched_private", "saw_untrusted")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, c.errAt(n, "when.session: needs touched_private and/or saw_untrusted")
	}
	out := make([]cond, 0, len(fields))
	for _, f := range fields {
		b, err := c.boolean(f.val, "session."+f.key.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, cond{cedar: "context.session." + f.key.Value + " == " + strconv.FormatBool(b)})
	}
	return out, nil
}

func (c compiler) toolLabel(n *yaml.Node) ([]cond, error) {
	l, err := c.label(n)
	if err != nil {
		return nil, err
	}
	return []cond{{cedar: `resource.labels.contains("` + l + `")`, callOnly: true}}, nil
}

// hourBetween: [start, end] -> start <= hour < end, on the daemon's clock.
func (c compiler) hourBetween(n *yaml.Node) ([]cond, error) {
	items, err := c.sequence(n, "hour_between")
	if err != nil {
		return nil, err
	}
	if len(items) != 2 {
		return nil, c.errAt(n, "hour_between needs exactly two hours: [start, end]")
	}
	start, err := c.integer(items[0], "hour_between start")
	if err != nil {
		return nil, err
	}
	end, err := c.integer(items[1], "hour_between end")
	if err != nil {
		return nil, err
	}
	switch {
	case start < 0 || start > 23:
		return nil, c.errAt(items[0], "hour_between start %d: want 0..23", start)
	case end < 1 || end > 24:
		return nil, c.errAt(items[1], "hour_between end %d: want 1..24", end)
	case start >= end:
		return nil, c.errAt(n, "hour_between [%d, %d] wraps around midnight or is empty: not expressible as one rule, split the rule into [%d, 24] and [0, %d]", start, end, start, end)
	}
	return []cond{{cedar: fmt.Sprintf("context.time.hour >= %d && context.time.hour < %d", start, end)}}, nil
}

// hostIn: [hosts] -> the normalised url host is one of them.
func (c compiler) hostIn(n *yaml.Node) ([]cond, error) {
	items, err := c.sequence(n, "host_in")
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, c.errAt(n, "host_in needs at least one host")
	}
	quoted := make([]string, 0, len(items))
	for _, it := range items {
		h, err := c.str(it, "a host")
		if err != nil {
			return nil, err
		}
		if !hostRE.MatchString(h) || len(h) > 253 {
			return nil, c.errAt(it, "host %q: want a lowercase ASCII host name like docs.python.org (no scheme, port, path or wildcard)", h)
		}
		quoted = append(quoted, `"`+h+`"`)
	}
	return []cond{{
		cedar:    "context.norm has url && [" + strings.Join(quoted, ", ") + "].contains(context.norm.url.host)",
		callOnly: true,
	}}, nil
}
