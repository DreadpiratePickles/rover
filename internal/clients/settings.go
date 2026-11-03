package clients

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Claude Code hardening (plan M7): permissions.deny rules in the user's
// ~/.claude/settings.json that stop Claude Code's own file tools from
// editing Rover's files and the client configs. Syntax checked 2026-10-09
// against https://code.claude.com/docs/en/permissions: Edit(path) rules use
// gitignore patterns, "~/" anchors at the home directory and "//" at the
// file system root, and deny rules are evaluated before allow rules in every
// scope. They are defence in depth: they bind Claude's tools and the shell
// commands Claude Code recognises, not every program the agent can run.

// SettingsPath is ~/.claude/settings.json.
func SettingsPath(home string) string { return filepath.Join(home, ".claude", "settings.json") }

// DenyRules returns the Edit deny rules protecting configDir, stateDir,
// ~/.claude.json and ~/.cursor/mcp.json, without duplicates. A path with
// gitignore metacharacters is refused rather than escaped: a mis-escaped
// pattern could protect nothing.
func DenyRules(home, configDir, stateDir string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string, dir bool) error {
		pat, err := denyPattern(home, p)
		if err != nil {
			return err
		}
		if dir {
			pat += "/**"
		}
		r := "Edit(" + pat + ")"
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
		return nil
	}
	for _, d := range []string{configDir, stateDir} {
		if err := add(d, true); err != nil {
			return nil, err
		}
	}
	for _, f := range []string{filepath.Join(home, ".claude.json"), filepath.Join(home, ".cursor", "mcp.json")} {
		if err := add(f, false); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func denyPattern(home, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	if strings.ContainsAny(p, `*?[]\!#`) {
		return "", fmt.Errorf("%q contains gitignore pattern characters; add its deny rule by hand", p)
	}
	if rel, err := filepath.Rel(home, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel), nil
	}
	return "/" + filepath.ToSlash(p), nil // "//abs": absolute from the root
}

// DenyJSON is the fragment the user is shown before anything is written.
func DenyJSON(rules []string) string {
	var sb strings.Builder
	sb.WriteString("{\n  \"permissions\": {\n    \"deny\": [\n")
	for i, r := range rules {
		sb.WriteString("      ")
		sb.Write(jsonString(r))
		if i < len(rules)-1 {
			sb.WriteByte(',')
		}
		sb.WriteByte('\n')
	}
	sb.WriteString("    ]\n  }\n}\n")
	return sb.String()
}

// PlanDeny merges rules into the settings file at path: only the rules not
// already in permissions.deny are added, spliced in like every other edit,
// so other settings keep their bytes and order. A missing file is created.
// settings.json is strict JSON (Claude Code rejects comments), and a file
// that does not parse is refused.
func PlanDeny(path string, rules []string) (Plan, error) {
	cf := ConfigFile{Adapter: NameClaudeSettings, Path: path, Scope: "user"}
	orig, err := readCapped(path)
	if errors.Is(err, os.ErrNotExist) {
		n := []byte(DenyJSON(rules))
		return Plan{File: cf, New: n, Created: true, Changed: rules,
			Diff: fmt.Sprintf("--- /dev/null\n+++ %s (rover)\n%s", path, prefixLines("+", string(n)))}, nil
	}
	if err != nil {
		return Plan{}, err
	}
	top, err := objectRange(orig, 0, len(orig))
	if err != nil {
		return Plan{}, fmt.Errorf("%s does not parse as strict JSON (%w); fix it before rover adds to it", path, err)
	}
	p := Plan{File: cf, Orig: orig}
	var e edit
	perms, ok := top.get("permissions")
	switch {
	case !ok:
		p.Changed = rules
		e = insertMember(orig, bytes.IndexByte(orig, '{'), top, "permissions", func(ind string) string {
			return "{\n" + ind + "  \"deny\": " + jsonArray(rules, ind+"  ") + "\n" + ind + "}"
		})
	default:
		pf, err := objectAt(orig, perms)
		if err != nil {
			return Plan{}, fmt.Errorf("%s: permissions: %w", path, err)
		}
		deny, ok := pf.get("deny")
		if !ok {
			p.Changed = rules
			e = insertMember(orig, perms.Start, pf, "deny", func(ind string) string { return jsonArray(rules, ind) })
			break
		}
		elems, err := arrayAt(deny)
		if err != nil {
			return Plan{}, fmt.Errorf("%s: permissions.deny: %w", path, err)
		}
		have := map[string]bool{}
		for _, el := range elems {
			if s, ok := stringValue(el.Value); ok {
				have[s] = true
			}
		}
		for _, r := range rules {
			if !have[r] {
				p.Changed = append(p.Changed, r)
			}
		}
		if len(p.Changed) == 0 {
			p.New = orig
			return p, nil
		}
		e = appendElements(orig, deny, elems, p.Changed)
	}
	return finish(p, []edit{e})
}

// insertMember adds "key": value as the last member of the object whose
// '{' is at objStart, indented like the members already there.
func insertMember(orig []byte, objStart int, members fields, key string, value func(indent string) string) edit {
	if len(members) == 0 {
		ind := lineIndent(orig, objStart) + "  "
		return edit{start: objStart + 1, end: objStart + 1, text: []byte("\n" + ind + `"` + key + `": ` + value(ind) + "\n" + lineIndent(orig, objStart))}
	}
	last := members[len(members)-1]
	ind := lineIndent(orig, last.Start)
	return edit{start: last.End, end: last.End, text: []byte(",\n" + ind + `"` + key + `": ` + value(ind))}
}

// appendElements adds strings at the end of an array, in its style: one
// per line if its elements are on separate lines, else ", "-separated.
func appendElements(orig []byte, arr field, elems []element, add []string) edit {
	var sb strings.Builder
	if len(elems) == 0 {
		for i, s := range add {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.Write(jsonString(s))
		}
		return edit{start: arr.Start + 1, end: arr.Start + 1, text: []byte(sb.String())}
	}
	sep := ", "
	if ws := orig[arr.Start+1 : elems[0].Start]; bytes.ContainsRune(ws, '\n') {
		sep = "," + string(ws)
	}
	for _, s := range add {
		sb.WriteString(sep)
		sb.Write(jsonString(s))
	}
	last := elems[len(elems)-1]
	return edit{start: last.End, end: last.End, text: []byte(sb.String())}
}

// jsonArray renders strings one per line, closing at indent.
func jsonArray(items []string, indent string) string {
	var sb strings.Builder
	sb.WriteString("[\n")
	for i, s := range items {
		sb.WriteString(indent + "  ")
		sb.Write(jsonString(s))
		if i < len(items)-1 {
			sb.WriteByte(',')
		}
		sb.WriteByte('\n')
	}
	sb.WriteString(indent + "]")
	return sb.String()
}

// lineIndent is the leading white space of the line holding offset off.
func lineIndent(b []byte, off int) string {
	start := bytes.LastIndexByte(b[:off], '\n') + 1
	end := start
	for end < len(b) && (b[end] == ' ' || b[end] == '\t') {
		end++
	}
	return string(b[start:end])
}

func prefixLines(mark, s string) string {
	var sb strings.Builder
	writeLines(&sb, mark, splitLines([]byte(s)))
	return sb.String()
}
