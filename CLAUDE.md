# Rover: instructions for Claude Code

Rover is an open-source (Apache-2.0) security layer for developers using AI agents. It has two parts:
- **rover-gate**, an MCP security gateway: a wrapper per server plus the `roverd` daemon, with Cedar policy.
- **rover-net**, policy as code for a Tailscale or Headscale tailnet.

**Read `docs/IMPLEMENTATION_PLAN.md` before doing anything.** It holds the locked decisions (§2), the threat model (§3), the architecture (§4), the policy model (§5) and the milestones (§6).

## Working rules
- Build **one milestone per branch and PR** (`m<N>-<slug>`), in the order of §6. Bobby said on 2026-10-09: keep going, no check-ins between milestones. So: open the PR, stack the next milestone's branch on it, and continue. He merges PRs himself; never merge or push to `main` from an agent.
- Every milestone is **verified by a separate agent** that gets the plan, the diff and the acceptance criteria and assumes the work is broken. Fix what it finds before stacking the next milestone on top.
- Delegate implementation to worker agents with a written brief (interfaces, tests, definition of done); the main session plans, reviews and integrates.
- Every milestone ends with `docs/lessons/<milestone>.md`, written for a security beginner. The format is in plan §0.4.
- 🔍 marks unverified facts. Check them against official docs or source before building on them, and use the stated fallback if they're false. If the plan says "stop and ask", stop.
- Never change a locked decision (§2) on your own. Raise it instead.
- Rover is meant to be a legitimate competitor to Gopher Security (plan §1), so build to production quality, not demo quality.
- Anything a human looks at follows plan §4.7: it looks exactly like cwm from OpenBSD.
- Work in this local checkout. Don't hand milestones to cloud sessions.

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
