package clients

import "fmt"

// The four clients of plan D11. Paths and keys were checked against each
// vendor's documentation on 2026-10-09; docs/adapters.md has the URLs.

// Claude Code: user and local scope in ~/.claude.json (user servers under
// the top-level "mcpServers", local ones under projects.<dir>.mcpServers),
// project scope in .mcp.json at the project root.
var claudeCodeSpec = spec{
	name: NameClaudeCode,
	files: func(e Env) ([]ConfigFile, error) {
		out := []ConfigFile{file(NameClaudeCode, "user", e.Home, ".claude.json")}
		if e.Cwd != "" {
			out = append(out, file(NameClaudeCode, "project", e.Cwd, ".mcp.json"))
		}
		return out, nil
	},
	containers: func(src []byte, top fields, scope string) ([]container, error) {
		var out []container
		c, err := serversIn(src, top, "mcpServers", scope)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
		projects, ok := top.get("projects")
		if !ok || isNull(projects) {
			return out, nil
		}
		pf, err := objectAt(src, projects)
		if err != nil {
			return nil, fmt.Errorf("projects: %w", err)
		}
		for _, p := range pf {
			if isNull(p) {
				continue
			}
			inner, err := objectAt(src, p)
			if err != nil {
				return nil, fmt.Errorf("projects[%q]: %w", p.Key, err)
			}
			c, err := serversIn(src, inner, "mcpServers", "local:"+p.Key)
			if err != nil {
				return nil, err
			}
			out = append(out, c...)
		}
		return out, nil
	},
}

// Cursor: ~/.cursor/mcp.json (global) and .cursor/mcp.json (project), both
// with "mcpServers".
var cursorSpec = spec{
	name: NameCursor,
	files: func(e Env) ([]ConfigFile, error) {
		global := file(NameCursor, "global", e.Home, ".cursor", "mcp.json")
		out := []ConfigFile{global}
		if e.Cwd != "" {
			if p := file(NameCursor, "project", e.Cwd, ".cursor", "mcp.json"); p.Path != global.Path {
				out = append(out, p)
			}
		}
		return out, nil
	},
	containers: mcpServersOnly("mcpServers"),
}

// Claude Desktop: macOS only. Anthropic documents macOS and Windows paths and
// ships no Linux build, so on Linux this adapter reports ErrUnsupported
// (the plan's fallback: skip with a message).
var claudeDesktopSpec = spec{
	name: NameClaudeDesktop,
	files: func(e Env) ([]ConfigFile, error) {
		if e.GOOS != "darwin" {
			return nil, fmt.Errorf("claude-desktop: %w: Claude Desktop documents config paths for macOS and Windows only", ErrUnsupported)
		}
		return []ConfigFile{file(NameClaudeDesktop, "user", e.Home, "Library", "Application Support", "Claude", "claude_desktop_config.json")}, nil
	},
	containers: mcpServersOnly("mcpServers"),
}

// VS Code (best effort): the workspace file .vscode/mcp.json, whose servers
// live under "servers" with an explicit "type". The user-profile mcp.json
// has no documented fixed path (it is opened with a command), so it is not
// detected.
var vscodeSpec = spec{
	name: NameVSCode,
	files: func(e Env) ([]ConfigFile, error) {
		if e.Cwd == "" {
			return nil, nil
		}
		return []ConfigFile{file(NameVSCode, "project", e.Cwd, ".vscode", "mcp.json")}, nil
	},
	containers: mcpServersOnly("servers"),
}

func mcpServersOnly(key string) func([]byte, fields, string) ([]container, error) {
	return func(src []byte, top fields, scope string) ([]container, error) {
		return serversIn(src, top, key, scope)
	}
}

// serversIn returns the server map under key, if there is one.
func serversIn(src []byte, obj fields, key, scope string) ([]container, error) {
	v, ok := obj.get(key)
	if !ok || isNull(v) {
		return nil, nil
	}
	m, err := objectAt(src, v)
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", key, scope, err)
	}
	return []container{{scope: scope, members: m}}, nil
}
