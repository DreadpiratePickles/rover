# Rover

A security-engineering learning project with two tracks:

- **rover-gate** is an MCP security gateway, run with the `rover` binary. It sits between AI agents and their MCP servers, and logs, inspects and polices every tool call.
- **rover-net** is a zero-trust network layer: policy as code for Tailscale, then Headscale, WireGuard and Rosenpass.

The full curriculum, with modules, labs and the Gopher parity map, is in the
"Rover: Security Engineering Curriculum" doc.

## Status

| Module | What | State |
| --- | --- | --- |
| A0 | Hand-written MCP server (`examples/echo-server`) | done |
| A1 | `rover wrap`: transparent stdio proxy + JSONL audit log | done |
| M0 | Repo hygiene: module rename, lint, CI, govulncheck | done |
| M1 | roverd, thin wrappers, hash-chained audit | done |
| — | Everything else | see docs/IMPLEMENTATION_PLAN.md |

## Quick start

```bash
make build          # -> bin/rover, bin/echo-server  (Go 1.25+)
make test           # unit + end-to-end tests with the race detector
make fuzz           # fuzz the parsers (JSON-RPC, audit lines, the roverd protocol)

# wrap any stdio MCP server (roverd starts automatically)
./bin/rover wrap -- npx -y @modelcontextprotocol/server-filesystem ~/lab
./bin/rover log            # the audit log as a timeline
./bin/rover log --verify   # check the audit log's hash chain
```

## Commands

```
rover wrap [--name N] -- <server command> [args...]
rover daemon [--log-bodies]
rover log [--log FILE] [--verify]
```

- **`rover wrap`** is what goes in the agent's MCP config, in front of the real server command. It is a thin wrapper: for every message, in both directions, it asks roverd what to do and does exactly that, forwarding the original bytes. `--name` sets the server name used in the audit log (default: the command's base name). Its stdout carries only MCP messages; everything else goes to stderr.
- **`rover daemon`** runs roverd, the one process per user that decides about every message and alone writes the audit log. It runs in the foreground and logs to stderr. Message bodies are **not** logged unless you pass `--log-bodies` (or set `ROVER_LOG_BODIES=1`, which also reaches an auto-started roverd), because Rover cannot redact secrets yet (M10).
- **`rover log`** prints the audit log as a timeline. `--verify` walks the hash chain (rotated files included) and prints `ok: N entries, chain intact`, or `BROKEN at <file>:<line>: <reason>` and exits 1.

### roverd

- **Auto-start.** If `rover wrap` cannot connect to roverd, it starts one (`rover daemon`, detached, output appended to `<state>/roverd.log`). A lock file stops several wrappers starting several daemons at once. `rover daemon` refuses to run twice for the same directories.
- **Fails closed.** If roverd still cannot be reached, the wrapper prints `roverd is not reachable; refusing to start <cmd> (fail closed)` to stderr, exits 3 and **never starts the MCP server**. If roverd goes away or stops answering mid-session, the wrapper kills the server and exits non-zero. Killing roverd is a denial of service, not a bypass.
- **Same user only.** The socket is `0600` in a `0700` directory, and roverd asks the kernel who is connecting (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) and hangs up on any other user. The wrapper checks the daemon the same way.
- **Sessions.** Wrappers started by the same agent app (same parent PID) share one roverd session, so later milestones can spot attacks that cross servers.
- **Tamper-evident audit log.** Each entry carries the SHA-256 of the previous one (`prev`) and its own (`hash`). The log rotates at 50 MiB, and each new file links to the last hash of the one before.

Exit codes of `rover wrap`: the server's own exit code when it ends normally; 1 on a setup or session error; 2 on a usage error; 3 when roverd is unreachable (the server was not started).

### Files

Directories are created `0700` and files `0600`; Rover refuses to run if a directory is looser, is a symlink or belongs to someone else.

| | macOS | Linux |
| --- | --- | --- |
| Config | `~/Library/Application Support/Rover/` | `$XDG_CONFIG_HOME/rover/` (fallback `~/.config/rover/`) |
| State: `rover.db`, `audit.jsonl`, `roverd.log` | `~/Library/Application Support/Rover/state/` | `$XDG_STATE_HOME/rover/` (fallback `~/.local/state/rover/`) |
| Run: `roverd.sock`, `roverd.pid`, `roverd.lock` | `~/Library/Application Support/Rover/run/` | `$XDG_RUNTIME_DIR/rover/` (fallback `$TMPDIR/rover-<uid>/`) |

- `ROVER_DIR=/abs/path` puts everything under one directory instead: config in it, state in `state/`, run files in `run/`. It is meant for tests and experiments.
- Unix socket paths are limited to about 104 bytes on macOS. If the socket path would be longer, it moves to `$TMPDIR/rover-<uid>/roverd.sock`.

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
docs/lessons/          one lesson per module
```

Each milestone ends with a beginner-friendly lesson in `docs/lessons/`.

## Development

```bash
make ci             # everything CI runs: vet, lint, race tests, fuzz, govulncheck
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
