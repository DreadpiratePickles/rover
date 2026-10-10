package propose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
)

// cedarRule renders one rule:
//
//	@id("learned-<server>-<tool>")
//	// derived from N calls between <first> and <last>: <Derived>
//	permit (principal, action == Action::"call_tool", resource == Tool::"s/t")
//	when { ... };
//
// Names and values were checked against safeName, safeHost and safeLiteral;
// the comment (which holds paths) goes through commentSafe.
func cedarRule(r ProposedRule, d draft) string {
	var b strings.Builder
	b.WriteString(`@id("` + r.ID + `")` + "\n")
	fmt.Fprintf(&b, "// derived from %d calls between %s and %s: %s\n",
		r.Calls, r.First.Format(time.RFC3339), r.Last.Format(time.RFC3339), commentSafe(r.Derived))
	switch d.action {
	case learn.ActionList:
		b.WriteString(`permit (principal, action == Action::"list_tools", resource == Server::"` + d.server + `");` + "\n")
		return b.String()
	default:
		b.WriteString("permit (\n  principal,\n  action == Action::\"call_tool\",\n  resource == Tool::\"" + d.server + "/" + d.tool + "\"\n)")
	}
	if len(d.conds) > 0 {
		parts := make([]string, len(d.conds))
		for i, c := range d.conds {
			parts[i] = "  " + c
		}
		b.WriteString("\nwhen {\n" + strings.Join(parts, " &&\n") + "\n}")
	}
	b.WriteString(";\n")
	return b.String()
}

// cedarStringSet renders ["a", "b"]; every element matched a safe pattern.
func cedarStringSet(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = `"` + s + `"`
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// jsonList renders a YAML flow sequence of quoted strings (JSON is YAML).
func jsonList(ss []string) string {
	b, _ := json.Marshal(ss)
	return string(b)
}

// commentSafe replaces anything that could end a // comment, so a path
// cannot inject Cedar into the output (as yaml2cedar does).
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\u0085' || r == ' ' || r == ' ' {
			return '_'
		}
		return r
	}, s)
}

func renderCedar(p Proposal) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Proposed by `rover policy propose` from %d observed calls (%d flagged, left out).\n", p.Used, len(p.Suspicious))
	b.WriteString("// Learn mode permits what it saw, mistakes included: review every rule before\n")
	b.WriteString("// `rover policy apply`. Anything no permit allows stays denied.\n")
	if len(p.NewRoots) > 0 {
		b.WriteString("// It uses roots config.yaml does not declare yet:\n")
		for _, r := range p.NewRoots {
			b.WriteString("//   " + r.Name + ": " + commentSafe(r.Path) + "\n")
		}
	}
	if len(p.Rules) == 0 {
		b.WriteString("// No rules: nothing unflagged was observed.\n")
	}
	for _, r := range p.Rules {
		b.WriteString("\n" + r.Cedar)
	}
	return b.Bytes()
}

// yamlRule is one rule of the YAML equivalent.
type yamlRule struct{ id, server, tool, when string }

// yamlRule records r's YAML form and returns it, or records why the
// proposal cannot have one.
func (b *builder) yamlRule(r ProposedRule, d draft) string {
	if d.action == learn.ActionList {
		return "" // implied by the server's allow rules; checked in renderYAML
	}
	if d.yamlNo != "" {
		if b.yamlWhy == "" {
			b.yamlWhy = r.ID + ": " + d.yamlNo
		}
		return ""
	}
	when := ""
	if len(d.yamlWhen) > 0 {
		when = "{ " + strings.Join(d.yamlWhen, ", ") + " }"
	}
	y := yamlRule{r.ID, d.server, d.tool, when}
	b.yamlBody = append(b.yamlBody, y)
	b.yamlOK[d.server] = true
	return y.text()
}

func (r yamlRule) text() string {
	s := fmt.Sprintf("  - id: %s\n    allow: %s\n", r.id, jsonString(r.server+"."+r.tool))
	if r.when != "" {
		s += "    when: " + r.when + "\n"
	}
	return s
}

// renderYAML writes the policy.yaml equivalent and compiles it to make sure
// it is one. It returns no YAML, and a note, when any rule has no YAML form.
func renderYAML(p Proposal, b *builder, labels map[string]map[string][]string) ([]byte, string) {
	if b.yamlWhy != "" {
		return nil, "no YAML equivalent: " + b.yamlWhy
	}
	for _, r := range p.Rules {
		if r.Action == learn.ActionList && !b.yamlOK[r.Server] {
			return nil, "no YAML equivalent: " + r.ID + ": YAML has no list_tools rule of its own (it is implied by an allow rule)"
		}
	}
	var out bytes.Buffer
	out.WriteString("# Proposed by `rover policy propose`: review every rule before applying it.\n")
	out.WriteString("# Its roots and labels replace config.yaml's when it is used as policy.yaml.\n")
	out.WriteString("# It compiles as mode: enforce: used as policy.yaml, anything not permitted is blocked.\n")
	out.WriteString("version: 1\nmode: enforce\ndefaults: deny\n")
	writeRoots(&out, b)
	writeLabels(&out, labels)
	if len(b.yamlBody) == 0 {
		out.WriteString("rules: []\n")
	} else {
		out.WriteString("rules:\n")
	}
	for _, r := range b.yamlBody {
		out.WriteString(r.text())
	}
	if _, err := yaml2cedar.Compile(out.Bytes(), "proposal.yaml"); err != nil {
		return nil, "no YAML equivalent: the generated YAML does not compile: " + err.Error()
	}
	return out.Bytes(), ""
}

func writeRoots(out *bytes.Buffer, b *builder) {
	if len(b.roots)+len(b.newRoots) == 0 {
		return
	}
	out.WriteString("roots:\n")
	for _, r := range b.roots {
		out.WriteString("  " + r.name + ": " + jsonString(r.path) + "\n")
	}
	for _, r := range b.newRoots {
		out.WriteString("  " + r.Name + ": " + jsonString(r.Path) + "\n")
	}
}

func writeLabels(out *bytes.Buffer, labels map[string]map[string][]string) {
	if len(labels) == 0 {
		return
	}
	out.WriteString("servers:\n")
	for _, s := range sortedMapKeys(labels) {
		out.WriteString("  " + jsonString(s) + ":\n    labels:\n")
		for _, t := range sortedMapKeys(labels[s]) {
			out.WriteString("      " + jsonString(t) + ": " + jsonList(labels[s][t]) + "\n")
		}
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
