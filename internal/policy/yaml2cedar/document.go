package yaml2cedar

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Names that end up inside Cedar text. They are restricted, not escaped:
// a name that would need escaping is refused, so YAML can never smuggle
// Cedar syntax (a quote, a newline, a comment) into the output.
var (
	// ruleIDRE: a rule id becomes @id("<id>").
	ruleIDRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	// serverRE: the part before the first "." of server.tool.
	serverRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// toolRE: a tool name (may contain dots).
	toolRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	// rootRE: a root name becomes the attribute under_<root>.
	rootRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	// hostRE: a host for host_in; lowercase because norm.url.host is.
	hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
)

// validLabels are the tool labels of plan §5.1.
var validLabels = map[string]bool{
	"reads_private": true, "reads_untrusted": true, "egress": true, "destructive": true,
}

var cedarReserved = map[string]bool{
	"true": true, "false": true, "if": true, "then": true, "else": true,
	"in": true, "is": true, "like": true, "has": true, "__cedar": true,
}

// parsed is the checked content of a policy.yaml.
type parsed struct {
	mode      string
	roots     map[string]string
	rootOrder []string
	labels    map[string]map[string][]string
	rules     []rule
}

func (p parsed) infos() []RuleInfo {
	out := make([]RuleInfo, len(p.rules))
	for i, r := range p.rules {
		out[i] = RuleInfo{ID: r.id, Line: r.line, Effect: r.effect(), Server: r.server, Tool: r.tool, Implied: r.implied}
	}
	return out
}

// document checks the top-level mapping.
func (c compiler) document(n *yaml.Node) (parsed, error) {
	fields, err := c.mapping(n, "policy.yaml", "version", "mode", "defaults", "servers", "roots", "rules")
	if err != nil {
		return parsed{}, err
	}
	p := parsed{roots: map[string]string{}, labels: map[string]map[string][]string{}}
	var sawVersion, sawDefaults bool
	var rulesNode *yaml.Node
	for _, f := range fields {
		switch f.key.Value {
		case "version":
			sawVersion = true
			err = c.version(f.val)
		case "mode":
			p.mode, err = c.mode(f.val)
		case "defaults":
			sawDefaults = true
			err = c.defaults(f.val)
		case "servers":
			p.labels, err = c.servers(f.val)
		case "roots":
			p.roots, p.rootOrder, err = c.roots(f.val)
		case "rules":
			rulesNode = f.val // checked last: rules refer to roots
		}
		if err != nil {
			return parsed{}, err
		}
	}
	if !sawVersion {
		return parsed{}, c.errAt(n, "missing \"version: 1\"")
	}
	if !sawDefaults {
		return parsed{}, c.errAt(n, "missing \"defaults: deny\" (Rover always denies what no rule allows; say so explicitly)")
	}
	if rulesNode != nil {
		if p.rules, err = c.rules(rulesNode, p.roots); err != nil {
			return parsed{}, err
		}
	}
	return p, nil
}

func (c compiler) version(n *yaml.Node) error {
	v, err := c.integer(n, "version")
	if err != nil {
		return err
	}
	if v != 1 {
		return c.errAt(n, "version %d is not supported (want 1)", v)
	}
	return nil
}

func (c compiler) mode(n *yaml.Node) (string, error) {
	m, err := c.str(n, "mode")
	if err != nil {
		return "", err
	}
	if m != "observe" && m != "enforce" {
		return "", c.errAt(n, "mode %q: want observe or enforce", m)
	}
	return m, nil
}

func (c compiler) defaults(n *yaml.Node) error {
	d, err := c.str(n, "defaults")
	if err != nil {
		return err
	}
	if d != "deny" {
		return c.errAt(n, "defaults %q: the only accepted value is deny (Rover never allows by default)", d)
	}
	return nil
}

// servers reads servers.<server>.labels.<tool>: [labels].
func (c compiler) servers(n *yaml.Node) (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{}
	if isNull(n) {
		return out, nil
	}
	servers, err := c.mapping(n, "servers")
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		if !serverRE.MatchString(s.key.Value) {
			return nil, c.errAt(s.key, "server name %q: only letters, digits, _ and - are allowed", s.key.Value)
		}
		inner, err := c.mapping(s.val, "servers."+s.key.Value, "labels")
		if err != nil {
			return nil, err
		}
		tools := map[string][]string{}
		for _, f := range inner {
			if tools, err = c.toolLabels(f.val, s.key.Value); err != nil {
				return nil, err
			}
		}
		out[s.key.Value] = tools
	}
	return out, nil
}

func (c compiler) toolLabels(n *yaml.Node, server string) (map[string][]string, error) {
	what := "servers." + server + ".labels"
	tools, err := c.mapping(n, what)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, t := range tools {
		if !toolRE.MatchString(t.key.Value) {
			return nil, c.errAt(t.key, "tool name %q: only letters, digits, _, . and - are allowed", t.key.Value)
		}
		items, err := c.sequence(t.val, what+"."+t.key.Value)
		if err != nil {
			return nil, err
		}
		labels := make([]string, 0, len(items))
		for _, it := range items {
			l, err := c.label(it)
			if err != nil {
				return nil, err
			}
			labels = append(labels, l)
		}
		out[t.key.Value] = labels
	}
	return out, nil
}

func (c compiler) label(n *yaml.Node) (string, error) {
	l, err := c.str(n, "a label")
	if err != nil {
		return "", err
	}
	if !validLabels[l] {
		return "", c.errAt(n, "unknown label %q (want reads_private, reads_untrusted, egress or destructive)", l)
	}
	return l, nil
}

// roots reads roots: {name: path}. Paths are kept as written; roverd
// expands "~".
func (c compiler) roots(n *yaml.Node) (map[string]string, []string, error) {
	out := map[string]string{}
	if isNull(n) {
		return out, nil, nil
	}
	fields, err := c.mapping(n, "roots")
	if err != nil {
		return nil, nil, err
	}
	order := make([]string, 0, len(fields))
	for _, f := range fields {
		name := f.key.Value
		if !rootRE.MatchString(name) || cedarReserved[name] {
			return nil, nil, c.errAt(f.key, "root name %q must be a Cedar identifier (letters, digits, _; not starting with a digit)", name)
		}
		path, err := c.str(f.val, "root "+name)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(path) == "" {
			return nil, nil, c.errAt(f.val, "root %s: empty path", name)
		}
		out[name] = path
		order = append(order, name)
	}
	return out, order, nil
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}
