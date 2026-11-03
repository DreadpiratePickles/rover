<div align="center">

# Rover

**A checkpoint between your AI agent and its tools.**

*Every tool call through Rover goes on the record first. If Rover can't record it, it doesn't happen.*

[![go](https://img.shields.io/badge/go-1.25+-00ADD8)](#install)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)](#files)

</div>

---

Your agent has a filesystem server, a shell server, a browser server and
whatever else you installed last Thursday. It calls them all day. It reads
files, runs commands and fetches pages, on your account, at machine speed.
Now: who is writing that down?

Usually nobody. The agent app shows you some of it, the MCP server logs what
it feels like, and the rest scrolls away. If a poisoned tool description or an
injected web page steers the agent into reading `~/.ssh` and posting it
somewhere, the record of that afternoon is whatever you happen to remember.

**Rover puts a checkpoint in the pipe.** It sits between the agent and each
stdio MCP server you wrap, sees every message in both directions, and writes each one
to an audit log that can't be quietly edited, *before* the message is allowed
through. If the log can't be written, the message doesn't go. If Rover itself
is down, your MCP servers don't start. It fails closed, every time.

Today Rover is the recorder and the gate. The policy engine that decides
*what* gets through is next, and is already built and in review (see
[Status](#status)).

## Status

Rover is built in the open, milestone by milestone, with a short lesson note
for each one in [`docs/lessons/`](docs/lessons/). It is pre-1.0 and has no
release yet. Here is exactly where it stands.

**On `main`, working, CI green on Linux and macOS:**

| Module | What |
| --- | --- |
| A0 | A hand-written MCP server with no SDK (`examples/echo-server`) |
| A1 | `rover wrap`: a transparent stdio proxy with a JSONL audit log |
| M0 | Repo hygiene: lint, CI, fuzzing, govulncheck, pinned tools |
| M1 | roverd, thin wrappers, same-user socket auth, hash-chained audit log |

On `main`, roverd's verdict is always "forward": it logs every message first
and forwards it, and blocks only when the audit log can't be written. It does
not yet allow or deny by policy.

**Built, in open pull requests, not on `main`:**

- The M1 on `main` came in through a parallel, unreviewed branch. A revert is
  open (#14), and the reviewed M1 is #4, which also carries **M2: the Cedar
  policy engine**.
- #15 brings the rest of the reviewed stack: **M3** YAML-to-Cedar policy
  compiler, **M4** tool pinning (rug-pull defence), **M5** detection tier 1 and
  an evaluation corpus, **M6** learn mode and policy proposals, **M7** client
  installers and `rover doctor`, **M8** session context and the "lethal
  trifecta", **M9** human approvals with OS authentication.
- Stacked on that: **M10** secrets and data-loss prevention (#16) and **M11**
  a bridge for remote MCP servers over Streamable HTTP with OAuth 2.1 (#17).

Until these merge, treat them as work in progress. The commands and behaviour
below describe `main` only.

**Planned, not built:** detection tiers 2 and 3 (M12), observability (M13),
hardening for 1.0 (M14), and **rover-net** (N1 to N6): a zero-trust network
layer that manages a Tailscale or Headscale tailnet as code, with just-in-time
access, device posture and quarantine, and post-quantum key exchange on
WireGuard via Rosenpass. None of rover-net exists yet. The full roadmap is in
[`docs/IMPLEMENTATION_PLAN.md` §6](docs/IMPLEMENTATION_PLAN.md#6-milestones).

## How it works

```
 agent app ──stdio──▶ rover wrap ──stdio──▶ MCP server
                          │
                          │  "may this message pass?"   (Unix socket, same user only)
                          ▼
                       roverd ──▶ audit.jsonl  (SHA-256 hash chain)
```

- **`rover wrap`** goes in your agent's MCP config in front of the real server
  command. It is deliberately thin: for every message, in both directions, it
  asks roverd what to do and does exactly that, forwarding the original bytes
  untouched.
- **roverd** is one daemon per user. It decides about every message and is the
  only thing that writes the audit log. Wrappers started by the same agent app
  share one session, so later milestones can spot attacks that cross servers.

## Install

You need Go 1.25+ and macOS or Linux.

```bash
git clone https://github.com/DreadpiratePickles/rover && cd rover
make build          # -> bin/rover, bin/echo-server
make test           # vet + unit and end-to-end tests with the race detector
```

## Usage

```bash
# wrap any stdio MCP server (roverd starts automatically)
./bin/rover wrap -- npx -y @modelcontextprotocol/server-filesystem ~/lab

./bin/rover log            # the audit log as a timeline
./bin/rover log --verify   # check the hash chain end to end
```

In an agent's MCP config, that looks like:

```json
"filesystem": {
  "command": "/path/to/rover",
  "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/lab"]
}
```

### Commands

```
rover wrap [--name N] -- <server command> [args...]
rover daemon [--log-bodies]
rover log [--log FILE] [--verify]
```

- **`rover wrap`** proxies one MCP server. `--name` sets the server name used
  in the audit log (default: the command's base name). Its stdout carries only
  MCP messages; everything else goes to stderr.
- **`rover daemon`** runs roverd in the foreground, logging to stderr. Message
  bodies are **not** logged unless you pass `--log-bodies` (or set
  `ROVER_LOG_BODIES=1`, which also reaches an auto-started roverd), because
  Rover on `main` cannot redact secrets yet.
- **`rover log`** prints the audit log as a timeline. `--verify` walks the hash
  chain, rotated files included, and prints `ok: N entries, chain intact`, or
  `BROKEN at <file>:<line>: <reason>` and exits 1.

Exit codes of `rover wrap`: the server's own exit code when it ends normally;
1 on a setup or session error; 2 on a usage error; 3 when roverd is
unreachable (the server was never started).

## The guarantees

- **Fails closed.** If `rover wrap` can't reach roverd, it starts one. If it
  still can't, it prints `roverd is not reachable; refusing to start <cmd>
  (fail closed)`, exits 3 and **never starts the MCP server**. If roverd goes
  away or stops answering mid-session, the wrapper kills the server and exits
  non-zero. Killing roverd is a denial of service, not a bypass.
- **Log first, then forward.** roverd writes each message to the audit log
  before telling the wrapper to forward it. If the write fails, the message is
  blocked.
- **Tamper-evident audit log.** Each entry carries the SHA-256 of the previous
  entry (`prev`) and its own (`hash`), so `rover log --verify` can name the
  file and line where an edited entry breaks the chain. The log rotates at 50 MiB, and each new file links to the last hash of the
  one before.
- **Same user only.** The socket is `0600` in a `0700` directory, and roverd
  asks the kernel who is on the other end (`SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on macOS) and hangs up on anyone else. The wrapper checks
  the daemon the same way.
- **Fuzzed where it parses.** The JSON-RPC classifier, the audit-line verifier
  and the wrapper-to-roverd protocol decoder all have fuzz targets, and CI
  runs them on every push and pull request.

### roverd details

- **Auto-start.** A wrapper that can't connect starts `rover daemon`, detached,
  with output appended to `<state>/roverd.log`. A lock file stops several
  wrappers starting several daemons at once, and `rover daemon` refuses to run
  twice for the same directories.
- **Private files.** Directories are created `0700` and files `0600`. Rover
  refuses to run if a directory is looser, is a symlink or belongs to someone
  else.

### Files

| | macOS | Linux |
| --- | --- | --- |
| Config | `~/Library/Application Support/Rover/` | `$XDG_CONFIG_HOME/rover/` (fallback `~/.config/rover/`) |
| State: `rover.db`, `audit.jsonl`, `roverd.log` | `~/Library/Application Support/Rover/state/` | `$XDG_STATE_HOME/rover/` (fallback `~/.local/state/rover/`) |
| Run: `roverd.sock`, `roverd.pid`, `roverd.lock` | `~/Library/Application Support/Rover/run/` | `$XDG_RUNTIME_DIR/rover/` (fallback `$TMPDIR/rover-<uid>/`) |

- `ROVER_DIR=/abs/path` puts everything under one directory instead: config in
  it, state in `state/`, run files in `run/`. It is meant for tests and
  experiments.
- Unix socket paths are limited to about 104 bytes on macOS. If the socket path
  would be longer, it moves to `$TMPDIR/rover-<uid>/roverd.sock`.

## Layout

```
cmd/rover/             CLI: wrap, daemon, log
internal/paths/        where Rover keeps its files; private-directory checks
internal/ipc/          the wrapper <-> roverd protocol over a Unix socket; peer credentials (fuzzed)
internal/daemon/       roverd: sessions, the decision path, audit ownership
internal/state/        bbolt state database
internal/proxy/        the wrapper's pump: ask roverd, apply the verdict; byte-exact, size-limited
internal/jsonrpc/      classify JSON-RPC messages (fuzzed)
internal/audit/        hash-chained JSONL audit log, rotation, verification (fuzzed)
examples/echo-server/  A0: MCP server with no SDK (read_file is unsafe on purpose)
docs/lessons/          one lesson note per module
```

## Development

```bash
make ci             # everything CI runs: vet, lint, race tests, fuzz, govulncheck
make fuzz           # fuzz the parsers (JSON-RPC, audit lines, the roverd protocol)
make lint           # golangci-lint only
make vuln           # govulncheck only
make tools          # install the pinned govulncheck
```

Tools:

- Go 1.25+. `go.mod` pins the toolchain, and Go downloads it if yours is older
  (unless `GOTOOLCHAIN=local`).
- [golangci-lint](https://golangci-lint.run) v2.5.0, installed from the release
  binary (see the `tools` target in the Makefile).
- govulncheck v1.7.0 (`make tools`), with `$(go env GOPATH)/bin` on your `PATH`.

CI (`.github/workflows/ci.yml`) runs the same checks on Linux and macOS for
every push to `main` and every pull request, with every third-party action
pinned to a commit SHA and a read-only token. See
[CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.

## Security

Rover is a security tool, so a bug in it matters. Please report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a
public issue. The threat model is in
[`docs/IMPLEMENTATION_PLAN.md` §3](docs/IMPLEMENTATION_PLAN.md#3-threat-model).
In short: Rover is designed against malicious MCP servers and agents steered
by injected content; on `main` it records and fails closed, and blocking by
policy arrives with M2. It does not defend against malware already
running as your user, and Windows is not supported.

### Lab rules

`examples/echo-server` is unsafe on purpose. Attack only machines you own, run
hostile test servers in containers, and never use real credentials in the lab.

## License

[Apache-2.0](LICENSE).
