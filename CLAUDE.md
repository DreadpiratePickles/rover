# Rover: instructions for Claude Code

Rover is an open-source (Apache-2.0) security layer for developers using AI agents. It has two parts:
- **rover-gate**, an MCP security gateway: a wrapper per server plus the `roverd` daemon, with Cedar policy.
- **rover-net**, policy as code for a Tailscale or Headscale tailnet.

**Read `docs/IMPLEMENTATION_PLAN.md` before doing anything.** It holds the locked decisions (§2), the threat model (§3), the architecture (§4), the policy model (§5) and the milestones (§6).

## Working rules
- Build **one milestone per branch and PR** (`m<N>-<slug>`), in the order of §6. After each milestone, **stop and wait** for Bobby to say "next". He's learning each milestone at about 10 hours a week, so don't run ahead.
- Every milestone ends with `docs/lessons/<milestone>.md`, written for a security beginner. The format is in plan §0.4.
- 🔍 marks unverified facts. Check them against official docs or source before building on them, and use the stated fallback if they're false. If the plan says "stop and ask", stop.
- Never change a locked decision (§2) on your own. Raise it instead.

## Security engineering rules (non-negotiable)
- **Fail closed.** An error on any decision path means deny, block or stop.
- **Forward the original bytes.** Never re-encode a message you've inspected.
- Every parser of attacker-controlled input has size and depth limits, and a fuzz target in `make fuzz`.
- Never write secrets to disk or logs. Never write anything except MCP protocol messages to stdout in `wrap` or `bridge`.
- Approvals and policy changes must never be possible through anything the agent can reach (HTTP, CLI, files). Only the OS authentication dialog counts.
- Time-based logic uses an injected clock in tests.
- Every new dependency needs a one-line justification in the PR. Prefer the standard library.

## Commands
- `make build`, `make test` (vet + race tests), `make fuzz`, `make ci` once M0 adds it.
- Go 1.25+ (after M0).

## Layout
- `cmd/` holds binaries.
- `internal/` holds packages: `jsonrpc`, `proxy`, `audit`, and, as the plan adds them, `ipc`, `daemon`, `policy`, `detect`, `dlp`, `approve`, `clients`, `net/...`.
- `examples/` holds demo servers.
- `testdata/` holds evil servers and the detection corpus.
- `docs/lessons/` holds the teaching notes.
