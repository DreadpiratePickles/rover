# Client adapters

`rover install` rewrites an agent client's MCP configuration so that every
local (stdio) server runs behind `rover wrap`. `rover uninstall` undoes it.
The code is in `internal/clients`; this page records what each client's
configuration looks like and how to add a new client.

## Verified facts (plan §8)

Each fact below was checked against the vendor's official documentation on
**2026-10-09**. If a vendor changes its format, re-check it here before
changing the adapter.

| Fact | Source | Result |
| --- | --- | --- |
| Claude Code: local and user scope live in `~/.claude.json`; project scope in `.mcp.json` at the project root | https://code.claude.com/docs/en/mcp (scope table) | Confirmed. Local scope is `projects.<project dir>.mcpServers` inside `~/.claude.json`. |
| Claude Code: user scope is the top-level `mcpServers` key of `~/.claude.json` | https://code.claude.com/docs/en/claude-directory (the `.claude.json` entry and its example) | Confirmed: the example shows a top-level `"mcpServers"` object. |
| Claude Code server fields | https://code.claude.com/docs/en/mcp | stdio: `type` (`"stdio"` or absent), `command`, `args`, `env`. Remote: `type` (`http`, `sse`, `ws`), `url`, `headers`. |
| Claude Code `permissions.deny` syntax | https://code.claude.com/docs/en/permissions | Confirmed. `Edit(path)` rules use gitignore patterns; `~/path` is anchored at the home directory and `//path` at the file-system root; rules are evaluated deny first, then ask, then allow, and a deny in any scope beats an allow in any other. |
| Claude Code settings file and strictness | https://code.claude.com/docs/en/settings | `~/.claude/settings.json` is the user file. It is strict JSON: a `//` comment or a trailing comma is a syntax error. |
| Cursor: `~/.cursor/mcp.json` (global) and `.cursor/mcp.json` (project), key `mcpServers` | https://cursor.com/docs/context/mcp | Confirmed. The field list marks `type` as required (`"stdio"` for local servers), though its examples omit it; stdio: `command`, `args`, `env`; remote: `url`, `headers`. Rover follows the field list: a `url` with no `type` is refused (see below). |
| Claude Desktop config path | https://modelcontextprotocol.io/docs/develop/connect-local-servers | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`. Windows: `%APPDATA%\Claude\claude_desktop_config.json`. **No Linux path is documented** ("available for macOS and Windows"). |
| VS Code workspace config | https://code.visualstudio.com/docs/copilot/customization/mcp-servers and https://code.visualstudio.com/docs/agents/reference/mcp-configuration | `.vscode/mcp.json`, top-level `servers`, `type` required (`stdio`, `http`, `sse`); stdio adds `command`, `args`, `env`, `envFile`; remote adds `url`, `headers`. The user-profile `mcp.json` is opened with a command and has no documented fixed path. |

Fallbacks applied (plan §8):

- **Claude Desktop on Linux:** no official path, so the adapter reports
  "not supported on this platform" and is skipped with that message.
- **VS Code user profile:** no documented path, so only the workspace file
  `.vscode/mcp.json` is handled (best effort, plan D11).
- **Claude Code hardening:** the syntax was confirmed, so the deny rules are
  proposed and merged. A rover path containing gitignore metacharacters
  (`* ? [ ] \ ! #`) is not escaped: the hardening step prints the rules and
  asks you to add them by hand.
- **Not handled:** `CLAUDE_CONFIG_DIR` (it moves Claude Code's settings);
  rover still looks in `~/.claude.json` and `~/.claude/settings.json`.

## What an adapter does

| Adapter | Files | Server map |
| --- | --- | --- |
| `claude-code` | `~/.claude.json` (user), `./.mcp.json` (project) | `mcpServers`, and `projects.*.mcpServers` in `~/.claude.json` |
| `cursor` | `~/.cursor/mcp.json` (global), `./.cursor/mcp.json` (project) | `mcpServers` |
| `claude-desktop` | macOS only: `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| `vscode` | `./.vscode/mcp.json` | `servers` |

The rewrite of one server, the same for every adapter:

```
{"command": "npx", "args": ["-y", "pkg"], "env": {...}}
->
{"command": "/abs/path/rover", "args": ["wrap", "--name", "<key>", "--", "npx", "-y", "pkg"], "env": {...}}

{"command": "npx"}                      (no args member)
->
{"command": "/abs/path/rover", "args": ["wrap", "--name=<key>", "--", "npx"]}
```

- `env` and every other member are untouched. `<key>` is the server's key,
  with any character outside `A-Za-z0-9_.-` replaced by `_`.
- A server that already runs `rover wrap` through this binary is left alone,
  so a second install changes nothing.
- A server wrapped by a *different* binary called `rover` is left alone
  with a warning, and `rover doctor` fails on it.
- An explicit `type` decides: `stdio` is local; `http`, `sse`, `ws` are
  remote and left alone with a warning until `rover bridge` (M11).
- Anything not understood (no `command`, a non-string argument, a `url`
  with no `type`, an unknown `type`, keys that differ only in case) makes
  install **refuse the whole file**, naming the servers: rover does not wrap
  part of a file it cannot fully read. Two keys that become the same
  `--name` after sanitising are refused the same way.
- Every diff shows `env` and `headers` values as `"[redacted]"`.

### Byte preservation

A config is never decoded into Go values and encoded back. The file is read
with the strict reader (`jsonrpc.Object`: exact keys, keys equal under case
folding refused, every value's byte offsets known). Comments and trailing
commas are first blanked to spaces in a working copy, so offsets still point
into the original. Then only two spans change per server: the `command`
value is replaced, and the wrap prefix is inserted at the start of `args`
(or a new `args` member is added after `command`, written with
`--name=<key>` as one element so the unwrap knows the member was not there
before: without that marker `{"command":"x"}` and `{"command":"x","args":[]}`
would wrap to the same bytes). The unwrap reads the fixed positions of
`wrap [--name K | --name=K] -- <command> <args...>` (so a server called
`--` is no problem), puts back the command's original bytes, and removes
exactly the prefix and separator install inserted, or the whole member when
install added it. Unknown keys, key order, spacing and comments survive.

### Writes and backups

`Apply` checks the file still holds the bytes the plan was made from, copies
them to `<state>/backups/<adapter>/<sha256 of the path>/<unix nanos>.json`
(0600, directory 0700) beside a `manifest.json` that records the backup's
sha256 and the sha256 of what rover wrote, writes the new bytes to a
temporary file in the same directory, fsyncs it, renames it over the config
and fsyncs the directory. A symlinked config is followed, so the link stays
a link. The newest five backups are kept.

`Restore` puts the newest backup back only if the file still has exactly the
bytes rover wrote and the backup still matches its sha256. Otherwise it
refuses and says why. `rover uninstall` then undoes the wrapping in place
when the file was edited since (Claude Code rewrites `~/.claude.json` all the
time), and stops for a backup that fails its checksum.

## Adding a client

1. Find the client's official documentation for its MCP config: file paths
   per platform, the key of the server map, and the stdio and remote fields.
   Add a row to the table above with the URL and the date.
2. Add a `spec` in `internal/clients/specs.go`. The example is a sketch:
   its path is illustrative, not verified.

   ```go
   var windsurfSpec = spec{
       name: "windsurf",
       files: func(e Env) ([]ConfigFile, error) {
           return []ConfigFile{file("windsurf", "user", e.Home, ".codeium", "windsurf", "mcp_config.json")}, nil
       },
       containers: mcpServersOnly("mcpServers", "user"),
   }
   ```

   `files` lists candidate paths; `Detect` keeps those that exist. Return
   `ErrUnsupported` (wrapped with a reason) on a platform with no documented
   path. `containers` finds the server maps; write your own function if they
   are nested, like `claudeCodeSpec` does for `projects`.
3. Register it in `specs` in `internal/clients/clients.go`.
4. Add a fixture config to `internal/clients/testdata/`, with its odd spacing,
   comments if the client allows them, unknown keys and a remote entry, and
   add it to `fixtures` in `clients_test.go`. Run
   `go test ./internal/clients -update` once, read the `.golden` file it
   writes, and commit both. The test checks install then uninstall is
   byte-identical, install twice is a no-op, and the unwrap is the inverse.
5. If the client's servers can carry fields that change how they start (as
   `envFile` does in VS Code), say so in the lesson; rover wraps the
   command, not the environment.
