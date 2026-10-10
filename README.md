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
| M3 | YAML → Cedar compiler (`rover policy compile`, `policy init --yaml`), schema generated from config | done |
| M4 | Tool pinning (rug-pull defence): TOFU digests, changed/new tools filtered and blocked, `rover pin list/approve/reset` | done |
| M5 | Detection tier 1 (local rules: invisible characters, instruction phrases, exfil URLs, shadowing, ...), evaluation corpus, `rover eval` gates | done |
| M6 | Learn mode (observe records call shapes) and policy proposals: `rover policy propose/diff`, flagged calls excluded | done |
| M7 | Client installers (`rover install/uninstall`, Claude Code deny rules, `--service`), tamper watch, `rover doctor`, `rover version`, goreleaser snapshot | done |
| — | **Phase 1 complete: v0.1.0** (snapshot via `make snapshot`; tagging is Bobby's) | |
| M8 | Session context and the lethal trifecta: per-session taint flags across servers, built-in tool labels with a conservative default, `rover policy labels`, trifecta guard active in the starter | done |
| M9 | Approvals and OS authentication: `@rover_require("approval")` holds a call until the macOS authentication dialog (LocalAuthentication) or polkit says yes; MCP elicitation and a read-only details page inform; `rover policy apply` and `rover pin approve/reset` need the dialog; roverd loads only an approved policy hash | done, pending the macOS dialog spike (Bobby, see docs/lessons/M9-approvals.md) |
| M10 | Secrets and data-loss prevention: secrets in results and errors redacted before the model sees them, egress calls carrying a secret blocked, every audit entry and log line redacted (bodies now logged by default), egress allow-list template, DLP corpus and `rover eval` gates | done |
| — | **Phase 2 complete: v0.2.0** (snapshot via `make snapshot`; tagging is Bobby's) | |
| M11 | Remote servers through `rover bridge` | next |
| — | Everything else | see docs/IMPLEMENTATION_PLAN.md |

## Quick start

```bash
make build          # -> bin/rover, bin/echo-server  (Go 1.25+)
make test           # unit + end-to-end tests with the race detector
make fuzz           # fuzz every parser of attacker input for 30s each

# write a starter policy (it permits nothing) and config.yaml (observe mode)
./bin/rover policy init
$EDITOR ~/Library/Application\ Support/Rover/policy.cedar   # macOS; see "Where files live"
./bin/rover policy validate  # type-check it against the schema (and run `cedar validate` if installed)
./bin/rover policy labels    # each tool's labels and where they came from (built-in, config, default);
                             # the starter's trifecta guard blocks egress after private + untrusted
./bin/rover policy apply     # roverd shows the system authentication dialog (Touch ID or password;
                             # polkit on Linux) and loads the policy only on your yes. roverd loads ONLY
                             # the approved policy: edited files change nothing until apply. Needs the
                             # dialog to work from roverd (M9 spike (b), pending); with roverd stopped,
                             # apply runs in the CLI and shows the dialog itself

# or write the policy in YAML (plan §5.4) and read the Cedar it compiles to
./bin/rover policy init --yaml          # policy.yaml instead of policy.cedar
./bin/rover policy compile ~/Library/Application\ Support/Rover/policy.yaml
./bin/rover policy validate ~/Library/Application\ Support/Rover/policy.yaml
./bin/rover policy validate --print-schema   # the schema generated from your roots
# YAML session conditions: when: { session: { touched_private: true, servers_touched: [hr-db] } }

# wrap any stdio MCP server; roverd starts itself the first time
# (--name may only use A-Za-z0-9_.-)
./bin/rover wrap --name filesystem -- npx -y @modelcontextprotocol/server-filesystem ~/lab
./bin/rover log              # timeline of every message
./bin/rover log --verify     # check the hash chain, report the first break
./bin/rover daemon           # run roverd by hand to watch its log
./bin/rover daemon --no-bodies       # metadata only (bodies are logged by default, secrets redacted)
./bin/rover policy test audit.jsonl  # replay a log (bodies on, the default) through the current policy

# tool pinning (M4): the first tools/list of a server (and its cursor pages,
# for 60 s) is trusted and pinned; every tool member except _meta is hashed.
# Later a changed or new tool is hidden and its calls blocked (pin_mismatch)
./bin/rover pin list                 # pins, MISMATCH/new markers and a diff of each change
./bin/rover pin approve filesystem read_file 3f2a9c01b7de   # the digest prefix pin list printed;
                                     # refused if the tool changed again since; shows the OS dialog first
./bin/rover pin reset filesystem     # forget a server's pins (OS dialog first); next list is trusted on first use

# approvals (M9): a permit annotated @rover_require("approval") (in YAML:
# require: approval) holds the call. roverd notifies you with a link to a
# read-only details page (127.0.0.1, GET only, it cannot approve), asks the
# agent app too if it supports MCP elicitation (a decline denies), and shows
# the OS authentication dialog. Yes forwards the call; cancel, failure or no
# answer in approvals.timeout_s (default 120) returns "approval denied" /
# "approval timed out". Other calls keep flowing meanwhile. Observe mode never
# holds: it forwards and logs would_deny. The dialog, the notification and the
# page show the approval id's first 8 characters; at most 5 approvals per
# session and 20 in all are pending, more are denied at once.
./bin/rover approvals list           # pending approvals: id, client, server.tool, age, page link
./bin/rover install --polkit         # Linux: prints the sudo commands that install the polkit
                                     # action org.rover.approve (rover never runs sudo); without a
                                     # polkit agent (headless) every approval is denied: no_auth_agent

# detection tier 1 (M5): always on, in every mode. A poisoned tool is removed
# from tools/list; an injected result block is replaced or gets a warning.
./bin/rover eval                     # precision/recall/false positives on testdata/corpus, then the dlp
                                     # section on testdata/corpus/dlp; exit 1 if a gate fails

# secrets and DLP (M10): always on, in every mode. A secret in a tool result,
# structuredContent, resource or error becomes [REDACTED:<kind>] before the
# agent sees it (audit findings dlp:<kind>); a tools/call to an egress tool
# whose arguments carry one is blocked (secret_in_egress_args:<kind>); a
# non-egress tool gets its arguments unchanged. Kinds: aws-access-key,
# aws-secret, github-token, slack-token, slack-webhook, stripe,
# private-key-pem, jwt, http-auth, generic-credential, high-entropy; member
# names are redacted too; a result that redaction would grow past 16 MiB is
# replaced by "[Rover removed content: too many secrets to redact (N matches)]".
# To limit egress tools to trusted hosts, uncomment the egress allow-list at
# the end of policy.cedar (templates/egress-allowlist.cedar).

# learn mode (M6): in observe mode roverd records the shape of every call
# (resolved paths, hosts, short literals; never contents). Then:
./bin/rover policy propose --yaml    # Cedar (+ YAML) permitting what was seen; flagged calls
                                     # listed as "suspicious, not proposed"; new roots to add
./bin/rover policy propose --out proposal.cedar
./bin/rover policy diff              # current policy vs the proposal (or: policy diff FILE)

# client installers (M7): wrap every stdio server of Claude Code, Cursor,
# Claude Desktop (macOS) and VS Code (.vscode/mcp.json); each change is shown
# as a diff and asked about (y/N), the original is backed up under the state
# directory, and remote servers are left alone until M11
./bin/rover install --dry-run        # show every diff, write nothing
./bin/rover install                  # or: --client claude-code --yes
./bin/rover uninstall                # restore the backups (byte-identical) or unwrap in place
./bin/rover install --service        # launchd agent / systemd user unit for roverd (--yes loads it)
./bin/rover doctor                   # PASS/WARN/FAIL per check; --json for scripts; exit 1 on FAIL
./bin/rover version
make snapshot                        # goreleaser snapshot of the release archives (v0.2.0 after M10) into dist/
```

`rover install --client claude-code` also proposes `permissions.deny` rules
for `~/.claude/settings.json` (`Edit(...)` on Rover's config and state
directories, `~/.claude.json` and `~/.cursor/mcp.json`) and prints the JSON
before merging it. They are defence in depth: they stop Claude Code's file
tools, not every program an agent can run. roverd watches the configs and
raises a `tamper` alert (audit entry, notification, `rover doctor`) when a
wrapped server is unwrapped or pointed at another binary. See
[docs/adapters.md](docs/adapters.md) for the verified config paths and how to
add a client.

Detection tier 1 is a set of local rules (no model, nothing leaves the
machine): invisible Unicode, ANSI escapes, hidden HTML, known instruction
phrases, sensitive paths, markdown links that carry data out, base64 blobs,
descriptions that name another server's tool. It catches the known tricks and
their exact wording; it cannot catch a paraphrase ("pay no attention to what
you were told earlier") or an attack in a language the phrase list does not
speak. Tiers 2 (a local classifier) and 3 (an opt-in LLM judge) come in M12
(decision D7); until then the policy and the pins remain the real walls.

Rover denies by default: with no `policy.cedar` or `policy.yaml`, roverd blocks every
`tools/call`, `tools/list`, `resources/read`, sampling and elicitation request
(reason `no_policy`). `config.yaml` starts in `mode: observe`, where a denied
message is still forwarded and logged as `would_deny`; switch to
`mode: enforce` once `rover log` shows no surprises. Switching back from
enforce to observe needs `rover policy apply` and roverd's dialog like any
other policy change (if roverd cannot show the dialog it answers deny:
"no interactive authentication from the daemon; see the spike notes"; the
fallback is a signed helper app, plan §9). `rover policy init` asks the
dialog too: without a yes it records nothing and roverd runs enforce with no
policy. roverd distrusts a state.db it cannot have written (recreated, empty
of approvals, or with an approval newer than the audit log) and reports a
state reset; `rover doctor`
fails `policy-approval` when the files on disk are not the approved ones.
Lines that are not unambiguous JSON-RPC (unknown members, duplicate keys or
keys that differ only in case, such as `name` and `Name`) are blocked as
`invalid_jsonrpc` in every mode. Every server you permit
also needs a `list_tools` permit, or the agent never sees its tools (in
`policy.yaml` the compiler adds it for you).

The schema is generated from the configuration: every root under `roots:`
(say `work`) gives `context.norm.<arg>.under_work`, every attribute is
optional, and a policy must test it with `has` first
(`context.norm has path.under_work && context.norm.path.under_work`). A `has`
on an attribute the schema does not declare is refused at load, because it
would always be false. In a `policy.yaml`, every server with at least one
`allow:` rule also gets an implied `list_tools` permit (id
`<server>-list-tools`), so the agent can see the tools it may call; a server
with only deny rules gets none.

`rover install` does this for you; by hand, in an agent's MCP config, change

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
| Config: `policy.cedar` or `policy.yaml`, `config.yaml`, `schema.cedarschema`, `templates/` | `~/Library/Application Support/Rover/` | `$XDG_CONFIG_HOME/rover/` |
| State: `state.db`, `audit.jsonl`, `roverd.log`, `backups/` (client configs, M7) | `~/Library/Application Support/Rover/state/` | `$XDG_STATE_HOME/rover/` |
| Socket, lock and pid files | `~/Library/Application Support/Rover/run/` | `$XDG_RUNTIME_DIR/rover/` |

Which policy roverd loads: `policy.cedar` if it exists; otherwise
`policy.yaml`, compiled to Cedar at load; otherwise none (`no_policy`, every
policed message blocked). When `policy.yaml` is used, its `mode`, `roots` and
`labels` override `config.yaml`'s; normalisers always come from `config.yaml`.
roverd logs the choice at start. A `policy.yaml` that does not compile is
logged with `file:line:col` and leaves the previous policy (or none) in force.

`ROVER_DIR=/some/path` puts all three under one directory, which is how the
tests and the lessons keep a lab separate from real use. Directories are `0700`
and files `0600`; Rover refuses to run if it finds them looser. Message bodies
are logged by default since M10, and every audit entry, daemon log line,
learn-mode shape and approval record passes through secret redaction first.
`rover daemon --no-bodies`, or `audit.bodies: false` in config.yaml, logs
metadata only. Redaction catches the formats in internal/dlp and high-entropy
tokens, not every secret there is (a plain-English password, a key split
across two different results): keep the state directory private either way.

## Layout

```
cmd/rover/             CLI: wrap, daemon, log, policy, pin, eval, install, uninstall, doctor, version
internal/policy/       the Cedar decision point: Decide, tools/list hiding (fuzzed)
internal/policy/convert/    tool arguments -> Cedar values, with limits (fuzzed)
internal/policy/normalize/  path/url/... normalisers run before the policy (fuzzed)
internal/policy/yaml2cedar/ policy.yaml -> Cedar, strict, golden-tested (fuzzed)
internal/config/       config.yaml: mode, roots, tool labels, normalisers
policy/                the shipped schema, starter policies (Cedar, YAML) and templates (embedded)
internal/proxy/        the wrapper's pump: read, ask roverd, apply the verdict, forward the original bytes
internal/daemon/       roverd: accept loop, peer check, sessions, the decision path, tamper watch
internal/ipc/          wrapper <-> roverd protocol (fuzzed) and peer credentials
internal/audit/        hash-chained JSONL audit log and its verifier
internal/state/        bbolt database (pins from M4; approvals, ... from later milestones)
internal/detect/       detection tier 1: rules (fuzzed), rules/*.txt phrase lists, corpus evaluation
internal/dlp/          secret detectors (fuzzed), redaction (JSON-aware), DLP corpus evaluation
internal/jsonedit/     strict JSON walking and byte splicing shared by roverd and DLP
internal/pin/          tool pinning: canonical JSON + SHA-256 per tool (fuzzed), TOFU, mismatch tracking, diffs
internal/clients/      client config adapters: strict byte-preserving rewrite (fuzzed), backups, deny rules
internal/paths/        where files go, and the permission checks
internal/framing/      newline-delimited reading with a hard size limit
internal/jsonrpc/      classify JSON-RPC messages (fuzzed)
examples/echo-server/  A0: MCP server with no SDK (read_file is unsafe on purpose)
testdata/corpus/       M5: the evaluation corpus (benign, poisoning, injection, exfil), MIN_COUNTS, CHANGES.md
testdata/corpus/dlp/   M10: fake secrets and benign look-alikes, dlp/MIN_COUNTS
testdata/servers/rugpull/  M4 lab: evil server that changes a tool after its first list (build tag `lab`)
testdata/servers/leaky/    M10 lab: server that echoes text into every result channel (build tag `lab`)
docs/lessons/          one lesson per module
```

## Development

```bash
make ci             # everything CI runs: vet, lint, race tests, detection gates, 30s fuzz per parser, govulncheck
make lint           # golangci-lint only
make vuln           # govulncheck only
make tools          # install the pinned govulncheck
```

Tools needed:

- Go 1.25+. `go.mod` pins the toolchain, and Go downloads it if yours is older (unless `GOTOOLCHAIN=local`).
- [golangci-lint](https://golangci-lint.run) v2.14.0, installed from the release binary (see the `tools` target in the Makefile).
- govulncheck v1.7.0 (`make tools`), with `$(go env GOPATH)/bin` on your `PATH`.

CI (`.github/workflows/ci.yml`) runs the same checks on Linux and macOS for every push to `main` and every pull request.

## Lab rules

Attack only machines you own. Run the evil test servers in containers. Don't use real credentials in the lab.
