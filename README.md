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
| — | Everything else | see docs/IMPLEMENTATION_PLAN.md |

## Quick start

```bash
make build          # -> bin/rover, bin/echo-server  (Go 1.25+)
make test           # unit + end-to-end tests with the race detector
make fuzz           # fuzz the JSON-RPC parser for 30s

# wrap any stdio MCP server
./bin/rover wrap -- npx -y @modelcontextprotocol/server-filesystem ~/lab
./bin/rover log
```

Audit log: `~/.rover/audit.jsonl` (override with `--log` or `ROVER_LOG`), created with mode `0600`.

## Layout

```
cmd/rover/             CLI: wrap, log
internal/jsonrpc/      classify JSON-RPC messages (fuzzed)
internal/proxy/        the pump: log-then-forward, byte-exact, size-limited
internal/audit/        JSONL audit writer
examples/echo-server/  A0: MCP server with no SDK (read_file is unsafe on purpose)
docs/lessons/          one lesson per module
```

Each milestone ends with a beginner-friendly lesson in `docs/lessons/`.

## Development

```bash
make ci             # everything CI runs: vet, lint, race tests, 30s fuzz, govulncheck
make lint           # golangci-lint only
make vuln           # govulncheck only
make tools          # install the pinned govulncheck
```

Tools needed:

- Go 1.25+. `go.mod` pins the toolchain, and Go downloads it if yours is older (unless `GOTOOLCHAIN=local`).
- [golangci-lint](https://golangci-lint.run) v2.5.0, installed from the release binary (see the `tools` target in the Makefile).
- govulncheck v1.8.0 (`make tools`), with `$(go env GOPATH)/bin` on your `PATH`.

CI (`.github/workflows/ci.yml`) runs the same checks on Linux and macOS for every push to `main` and every pull request.

## Lab rules

Attack only machines you own. Run the evil test servers in containers. Don't use real credentials in the lab.
