# Rover

An open-source security layer for developers who use AI agents, built to stand
beside commercial products such as Gopher Security rather than demonstrate a
concept. Two tracks:

- **rover-gate** is an MCP security gateway, run with the `rover` binary. A thin
  wrapper sits between an AI agent and each MCP server it uses; a local daemon,
  `roverd`, sees every message, records it in a tamper-evident log, and (from M2)
  applies policy, pins tool definitions, detects attacks and asks a human before
  dangerous calls.
- **rover-net** is a zero-trust network layer: policy as code for Tailscale, then
  Headscale, WireGuard and Rosenpass.

The plan, threat model, architecture and milestones are in
[docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md). Every milestone ends
with a beginner-friendly lesson in [docs/lessons/](docs/lessons/).

## Status

| Module | What | State |
| --- | --- | --- |
| A0 | Hand-written MCP server (`examples/echo-server`) | done |
| A1 | `rover wrap`: transparent stdio proxy + JSONL audit log | done |
| M0 | Repo hygiene: module rename, lint, CI, govulncheck | done |
| M1 | `roverd` daemon, thin wrappers, peer-checked Unix socket, hash-chained audit log, auto-start | done |
| M2 | Cedar policy engine: default deny, hidden tools, argument normalisers, `rover policy init/validate/test/apply` | done |
| M3 | YAML → Cedar compiler | next |
| — | Everything else | see docs/IMPLEMENTATION_PLAN.md |

## Quick start

```bash
make build          # -> bin/rover, bin/echo-server  (Go 1.25+)
make test           # unit + end-to-end tests with the race detector
make fuzz           # fuzz every parser of attacker input for 30s each

# write a starter policy (it permits nothing) and config.yaml (observe mode)
./bin/rover policy init
$EDITOR ~/Library/Application\ Support/Rover/policy.cedar   # macOS; see "Where files live"
./bin/rover policy validate  # type-check it against the schema
./bin/rover policy apply     # ask a running roverd to reload it

# wrap any stdio MCP server; roverd starts itself the first time
./bin/rover wrap --name filesystem -- npx -y @modelcontextprotocol/server-filesystem ~/lab
./bin/rover log              # timeline of every message
./bin/rover log --verify     # check the hash chain, report the first break
./bin/rover daemon           # run roverd by hand to watch its log
./bin/rover policy test audit.jsonl  # replay a log (recorded with --log-bodies) through the current policy
```

Rover denies by default: with no `policy.cedar`, roverd blocks every
`tools/call`, `tools/list`, `resources/read`, sampling and elicitation request
(reason `no_policy`). `config.yaml` starts in `mode: observe`, where a denied
message is still forwarded and logged as `would_deny`; switch to
`mode: enforce` once `rover log` shows no surprises. Every server you permit
also needs a `list_tools` permit, or the agent never sees its tools.

Schema limitation until M3: a root you add under `roots:` in `config.yaml`
(say `work`) is only usable in policies as `context.norm.<arg>.under_work`
once `schema.cedarschema` in the config directory declares a matching
`under_work: Bool` attribute next to `under_projects`.

In an agent's MCP config, change

```json
"filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/lab"] }
```

to

```json
"filesystem": { "command": "/path/to/rover", "args": ["wrap", "--name", "filesystem", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/lab"] }
```

## Where files live

| | macOS | Linux |
| --- | --- | --- |
| Config: `policy.cedar`, `config.yaml`, `schema.cedarschema`, `templates/` | `~/Library/Application Support/Rover/` | `$XDG_CONFIG_HOME/rover/` |
| State: `state.db`, `audit.jsonl`, `roverd.log` | `~/Library/Application Support/Rover/state/` | `$XDG_STATE_HOME/rover/` |
| Socket, lock and pid files | `~/Library/Application Support/Rover/run/` | `$XDG_RUNTIME_DIR/rover/` |

`ROVER_DIR=/some/path` puts all three under one directory, which is how the
tests and the lessons keep a lab separate from real use. Directories are `0700`
and files `0600`; Rover refuses to run if it finds them looser. Message bodies
are not logged until M10 adds redaction (`rover daemon --log-bodies` turns them
on for a lab).

## Layout

```
cmd/rover/             CLI: wrap, daemon, log, policy
internal/policy/       the Cedar decision point: Decide, tools/list hiding (fuzzed)
internal/policy/convert/    tool arguments -> Cedar values, with limits (fuzzed)
internal/policy/normalize/  path/url/... normalisers run before the policy (fuzzed)
internal/config/       config.yaml: mode, roots, tool labels, normalisers
policy/                the shipped schema, starter policy and templates (embedded)
internal/proxy/        the wrapper's pump: read, ask roverd, apply the verdict, forward the original bytes
internal/daemon/       roverd: accept loop, peer check, sessions, the decision path
internal/ipc/          wrapper <-> roverd protocol (fuzzed) and peer credentials
internal/audit/        hash-chained JSONL audit log and its verifier
internal/state/        bbolt database (pins, approvals, ... from later milestones)
internal/paths/        where files go, and the permission checks
internal/framing/      newline-delimited reading with a hard size limit
internal/jsonrpc/      classify JSON-RPC messages (fuzzed)
examples/echo-server/  A0: MCP server with no SDK (read_file is unsafe on purpose)
docs/lessons/          one lesson per module
```

## Development

```bash
make ci             # everything CI runs: vet, lint, race tests, 30s fuzz per parser, govulncheck
make lint           # golangci-lint only
make vuln           # govulncheck only
make tools          # install the pinned govulncheck
```

Tools needed:

- Go 1.25+. `go.mod` pins the toolchain, and Go downloads it if yours is older (unless `GOTOOLCHAIN=local`).
- [golangci-lint](https://golangci-lint.run) v2.5.0, installed from the release binary (see the `tools` target in the Makefile).
- govulncheck v1.7.0 (`make tools`), with `$(go env GOPATH)/bin` on your `PATH`.

CI (`.github/workflows/ci.yml`) runs the same checks on Linux and macOS for every push to `main` and every pull request.

## Lab rules

Attack only machines you own. Run the evil test servers in containers. Don't use real credentials in the lab.
