# Rover

A security-engineering learning project with two tracks:

- **rover-gate** is an MCP security gateway. It sits between AI agents and their MCP servers, and logs, inspects and polices every tool call.
- **rover-net** is a zero-trust network layer: policy as code for Tailscale, then Headscale, WireGuard and Rosenpass.

The full curriculum, with modules, labs and the Gopher parity map, is in the
"Rover: Security Engineering Curriculum" doc.

## Status

| Module | What | State |
| --- | --- | --- |
| A0 | Hand-written MCP server (`examples/echo-server`) | done |
| A1 | `rover-gate wrap`: transparent stdio proxy + JSONL audit log | done |
| — | Everything else | see docs/IMPLEMENTATION_PLAN.md |

## Quick start

```bash
make build          # -> bin/rover-gate, bin/echo-server  (Go 1.24+)
make test           # unit + end-to-end tests with the race detector
make fuzz           # fuzz the JSON-RPC parser for 30s

# wrap any stdio MCP server
./bin/rover-gate wrap -- npx -y @modelcontextprotocol/server-filesystem ~/lab
./bin/rover-gate log
```

Audit log: `~/.rover/audit.jsonl` (override with `--log` or `ROVER_LOG`), created with mode `0600`.

## Layout

```
cmd/rover-gate/        CLI: wrap, log
internal/jsonrpc/      classify JSON-RPC messages (fuzzed)
internal/proxy/        the pump: log-then-forward, byte-exact, size-limited
internal/audit/        JSONL audit writer
examples/echo-server/  A0: MCP server with no SDK (read_file is unsafe on purpose)
docs/lessons/          one lesson per module
```

## Lab rules

Attack only machines you own. Run the evil test servers in containers. Don't use real credentials in the lab.
