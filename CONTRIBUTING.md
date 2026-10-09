# Contributing to Rover

Thanks for helping. Rover is a security tool, so the bar for changes is a
little higher than usual: every change should keep the gateway failing closed,
and every claim it makes should be backed by a test.

**Found a security bug?** Don't open an issue or a PR. Follow
[SECURITY.md](SECURITY.md) and report it privately.

## Prerequisites

- **Go 1.25 or newer.** `go.mod` pins the toolchain (`toolchain go1.25.14`),
  so if your local Go is at least 1.21 but older than go1.25.14, the `go`
  command downloads go1.25.14 for you and checks it against the Go checksum
  database.
- **govulncheck**, at the version pinned in the Makefile. Install it with:

  ```bash
  make tools
  ```

  Make sure `$(go env GOPATH)/bin` is on your `PATH`.
- **golangci-lint v2.5.0**, the same version CI uses. Upstream advises against
  `go install` for it, so download the release binary and check it against the
  checksums file from the same release. The comment above the `tools` target
  in the `Makefile` has the exact commands.
- macOS or Linux. Windows isn't supported yet.

## The build and test loop

```bash
make build   # builds bin/rover (and bin/echo-server)
make test    # go vet + go test -race ./...
make fuzz    # 30 s fuzz of the JSON-RPC parser
make lint    # golangci-lint
make vuln    # govulncheck ./...
make ci      # everything CI runs, in the same order: vet, lint, test -race, fuzz, govulncheck
```

Run `make ci` before you push. It mirrors the GitHub Actions workflow, so if
it's green locally, CI should be green too.

## How work is organised

- Work follows the milestones in
  [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) §6, **in order**.
  Read §2 (locked decisions) and §3 (threat model) before proposing a design.
- **One milestone per branch and pull request.** Name the branch
  `m<N>-<slug>`, for example `m2-cedar-engine`. Don't mix two milestones in one
  PR.
- Each milestone ends with a lesson in `docs/lessons/<milestone>.md`, written
  for someone new to security. The format is in the plan, §0 rule 4.
- Locked decisions (§2) don't change in a PR. If you think one is wrong, open
  an issue to discuss it first.

## Security engineering rules (non-negotiable)

These apply to every change. A PR that breaks one won't be merged, however
useful the rest of it is.

1. **Fail closed.** An error on any decision path means deny, block or stop.
   Never "allow and log".
2. **Forward the original bytes.** Never re-encode a message you've inspected.
   What Rover checked must be exactly what the server receives.
3. **Limit every parser of untrusted input.** Anything that parses
   attacker-controlled input has size and depth limits, and a fuzz target that
   runs in `make fuzz`.
4. **No secrets on disk or in logs.** Redact before writing anything.
5. **Nothing but MCP protocol messages on stdout** in `wrap` or `bridge`. Use
   stderr or the audit log for everything else; a stray `fmt.Println` corrupts
   the protocol stream.
6. **Approvals and policy changes only through the OS authentication dialog.**
   Never add a way to approve or change policy through anything the agent can
   reach: an HTTP endpoint, a CLI flag, a file, an environment variable.
7. **Inject the clock.** Time-based logic takes a clock you can control in
   tests; no `time.Sleep` in tests to wait for a timeout.

## Dependencies

- Prefer the standard library. Then well-known, maintained modules.
- **Every new dependency needs a one-line justification in the PR
  description**: what it does that the standard library can't, and why this
  module.
- Keep `go.mod` and `go.sum` committed and tidy (`go mod tidy`). Don't edit
  `go.sum` by hand, and never commit a change that weakens checksum
  verification (for example setting `GOSUMDB=off`, `GONOSUMDB`, `GOPRIVATE` or
  `GOINSECURE` in the Makefile or CI).

## Pull requests

- **Keep them small.** One milestone, or one focused fix. Small PRs get
  reviewed properly; big ones get skimmed.
- **Test the acceptance criteria.** Write the milestone's acceptance criteria as
  tests where you can. Bug fixes come with a test that fails without the fix.
- **Lint clean.** `make ci` passes with no new `//nolint` comments. If you
  really need one, say why on the same line.
- **Say what you verified.** The plan marks unconfirmed facts with 🔍. In the
  PR description, list each 🔍 fact you relied on, where you checked it
  (official docs or source), and what you found. If a fact was false, say
  which fallback you used.
- **Describe a manual demo**: what you ran, on which OS, and what you saw.

## License

Rover is licensed under the [Apache License 2.0](LICENSE). By contributing, you
agree that your contributions are licensed under the same terms (see section 5
of the license). There's no contributor license agreement (CLA) to sign.
