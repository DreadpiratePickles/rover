# M0 · Repo hygiene

**Goal:** before Rover gets more powerful, make sure `bin/rover` is the code
we meant to ship, built by the compiler we meant to use, and checked by
machines on every change. Lesson focus: supply chain basics.

```
your code ─┐
deps ──────┼─▶ go toolchain ─▶ bin/rover ─▶ decides every MCP call
CI actions ┘   (downloaded)
```

Everything left of `bin/rover` can change what it does. That's the supply chain.

## (a) What was built

Nothing a user would notice. M0 is plumbing:

- **A real name.** The module is now `github.com/DreadpiratePickles/rover`
  and the binary is `rover` (`cmd/rover`), with `wrap` and `log` as before.
- **A pinned compiler.** `go.mod` says `go 1.25` and `toolchain go1.25.14`.
- **Linters.** `.golangci.yml` turns on `govet`, `staticcheck`, `errcheck`,
  `gosec` and `revive` (plus a few small ones), with no blanket exclusions.
- **CI.** `.github/workflows/ci.yml` runs on every push to `main` and every
  PR: lint, `go test -race` on Linux *and* macOS, a 30 s fuzz of the JSON-RPC
  parser, and `govulncheck`. `make ci` runs the same checks locally.
- **Paperwork that matters:** `LICENSE` (Apache-2.0), `SECURITY.md` (a private
  channel for vulnerability reports, so the first news of a Rover bypass isn't
  a public issue) and `CONTRIBUTING.md` (the security rules, written down).

## (b) Design decisions and the attacks they prevent

### 1. Why a security tool is a juicy supply-chain target

A **software supply chain** is everything that touches your code between
someone typing it and it running on a machine: dependencies, the compiler,
build scripts, CI, the release pipeline. Attackers love it because it scales:
compromise one popular package and you're inside every machine that installed
it willingly.

Rover is a particularly good prize. It sits between an AI agent and every tool
the agent uses, and its whole job is to say "yes" or "no". A backdoored Rover
doesn't need an exploit: it says "yes" to the attacker's tool call and writes a
clean-looking audit log. So the first milestone is about trusting our own build
before we ask anyone to trust our decisions.

### 2. The module path is an identity

`module rover` worked on one laptop, but a path with no dot in its first
element can't be fetched with `go install`, and says nothing about where the
code comes from: anyone can call their project `rover`.
`github.com/DreadpiratePickles/rover` is a **name and an address**. When you
run `go install github.com/DreadpiratePickles/rover/cmd/rover@v0.1.0`, Go
fetches it through the **module proxy** (`proxy.golang.org`) and checks its
hash against the **checksum database** (`sum.golang.org`).

The checksum database is a **transparency log**: an append-only Merkle tree
holding the hash of every public module version anyone has fetched. Your `go`
command checks a signed proof that the hash it got is in the log, and that the
log hasn't been rewritten.

| Attack | Stopped? |
| --- | --- |
| Someone on the network swaps the zip you download | ✅ hash doesn't match the log |
| The maintainer (or a thief with their GitHub login) moves tag `v0.1.0` to new code | ✅ the log already has the old hash; Go refuses the new one |
| A proxy shows *you* different code from everyone else | ✅ your hash must be in the same public log everyone else checks |
| The code was malicious **from the first publish** | ❌ the log faithfully records the bad hash |
| A look-alike name (`DreadpiratePickle/rover`, missing `s`) | ❌ different name, different identity; you have to type it right |

The last two rows are real. In February 2025, Socket reported a backdoored
typosquat of `boltdb/bolt` published as `boltdb-go/bolt`. The proxy cached the
backdoored version; the attacker then pointed the GitHub tag at clean code, so
anyone reading GitHub saw clean code while `go get` served the backdoor.
Immutability protects you from changes, not from a bad first version.

### 3. `go` vs `toolchain` in go.mod

```
go 1.25
toolchain go1.25.14
```

- **`go 1.25`** is the minimum version; older Go refuses to build (M13 needs a
  1.25 TLS feature).
- **`toolchain go1.25.14`** is the toolchain to use if yours is older. With the
  default `GOTOOLCHAIN=auto`, Go 1.21+ downloads go1.25.14 as a module
  (`golang.org/toolchain`) and verifies it against `sum.golang.org` like any
  other module. If yours is *newer*, Go uses yours.

Why pin the patch number? Go's point releases are mostly security fixes in the
standard library: `net/http`, `crypto/tls`, `crypto/x509`, archive and
encoding parsers. Rover's dependencies are mostly the standard library, so
"which Go" is "which dependencies". A pinned patch means everyone builds with
at least the same fixes, `govulncheck` judges the stdlib you actually use,
and builds are easier to reproduce.

### 4. go.sum and trust on first use

`go.sum` lists a hash for every module version the build uses, and the `go`
command stops if a download differs. Rover has almost no third-party
dependencies yet, so its `go.sum` is short or missing. That's deliberate: the
smallest supply chain is the one you don't have.

The idea behind `go.sum` is **trust on first use (TOFU)**: the first time you
see something, you record what it looked like; after that, any change is an
alarm. SSH's `known_hosts` works the same way. The weakness is the first use:
if the first download was already evil, TOFU records evil.

The checksum database narrows that weakness: your "first use" is checked
against everyone else's. You'll meet TOFU again in **M4**, where Rover pins
each MCP tool's description on first sight and blocks the tool if it changes
later (a "rug pull").

### 5. Linters are security tools

A linter reads code without running it and flags patterns that are usually
bugs. In a security gateway, many of those bugs are vulnerabilities.

| Linter | Bug class it catches | Why it's a security problem here |
| --- | --- | --- |
| `go vet` | `Printf` format mismatches, copied mutexes, unreachable code, bad struct tags | A copied `sync.Mutex` protects nothing; two goroutines then share state unguarded |
| `staticcheck` | Deprecated APIs, conditions that are always true or false, results you forgot to use | A check that can never fire looks like protection in review, but isn't |
| `errcheck` | A returned error that's never looked at | `os.Chmod(log, 0o600)` fails, nobody checks, and the audit log stays world-readable: **failing open** |
| `gosec` | G302/G306 file modes looser than `0600`; G304 file paths from variables; G204 commands built from variables; weak crypto | A `0644` audit log leaks tool arguments; a path from untrusted input reads files you didn't intend |
| `revive` | Style, naming, missing doc comments | Code reviewers can only spot bugs in code they can read |

Two choices in `.golangci.yml` are worth noticing:

- **No exclusion presets.** Every warning is either fixed or suppressed with a
  `//nolint:<linter> // reason` comment, and `nolintlint` rejects suppressions
  without a reason. An unexplained suppression is a place where a bug can hide
  forever.
- `errcheck` allows `_ = f()`: a visible, reviewable decision to ignore an
  error. Forgetting is not.

### 6. The race detector

`internal/proxy` runs two goroutines per session, one per direction. Both
touch the `pending` map that matches responses to requests, protected by
`s.mu`. Remove that lock and you have a **data race**.

In a normal program a race is a crash or a wrong number. In a security
gateway it's an exploitable bug: an attacker who controls timing (a hostile
server can choose exactly when to reply) can try to make the gateway look up
the wrong request, log the wrong tool, or, later, apply the wrong policy
decision. Races hide in testing and appear under load.

`go test -race` instruments every memory access and reports two goroutines
touching the same memory without synchronisation. It only sees races that the
tests actually execute, so a test that drives both directions at once matters
as much as the flag. CI runs `-race` on Linux and macOS because scheduling
differs between them, and from M1 on some code (peer credentials on the
socket) is different on each OS.

### 7. govulncheck: reachability, not just a version list

Most CVE scanners read your dependency list and flag every module with a known
vulnerability. Most alarms are noise (the bug is in a function you never call),
so people learn to ignore the scanner, and then miss the real one.

`govulncheck` uses the curated Go vulnerability database (`vuln.go.dev`) and
then builds a **call graph** of your program. By default it reports a
vulnerability only if your code can actually reach the vulnerable function,
and it shows the call path. It covers the standard library too, based on your
Go version, which is one more reason to pin the toolchain.

It is still not enough:

- It only knows **known** vulnerabilities. A backdoor isn't in any database
  until someone finds it.
- It doesn't look at your own code for bugs. That's what linters, tests and
  fuzzing are for.
- New vulnerabilities are published against old code every week, so a green
  run today says nothing about next month.

### 8. GitHub Actions is attack surface

A workflow runs with access to your repository, and every `uses:` line runs
someone else's code inside it. What we did:

- **`permissions: contents: read`.** The automatic `GITHUB_TOKEN` can read the
  repo and nothing else: it can't push, tag, create releases, or edit issues
  and PRs. If a step is compromised, the stolen token can't change the code.
- **`persist-credentials: false`** on checkout, so the token isn't left in
  `.git/config` for later steps to find.
- **No secrets in this workflow.** It triggers on `pull_request`, which GitHub
  runs *without* repository secrets for pull requests from forks. Never switch
  to `pull_request_target` and check out the PR's code: that runs a
  stranger's code with your secrets (a "pwn request").
- **Every action pinned to a full commit SHA**, with the tag in a comment:
  `actions/checkout@3d3c42e…  # v7.0.1`.

Why SHAs and not `@v4`? A tag is just a movable label. On 14 March 2025, an
attacker with a stolen token for the popular action `tj-actions/changed-files`
(CVE-2025-30066) **moved many of its version tags** to a malicious
commit. That commit dumped the CI runner's memory, pulled out secrets and
printed them, base64-encoded twice, into the build log. Over 20,000
repositories used the action. Every workflow that said
`tj-actions/changed-files@v35` (or any other tag) ran the attacker's code on
its next run, and for public repositories the logs, with the secrets, were
public. Investigators linked the stolen token to an earlier compromise of
another action, `reviewdog/action-setup`: one supply-chain attack feeding the
next.

Workflows pinned to a commit SHA kept running clean code: a SHA is a hash of
the content and can't be moved. The cost is that pins don't update
themselves; a bot such as Dependabot proposes updates and a human reviews them.

### 9. Fuzzing in CI

A fuzzer generates millions of strange inputs, keeps the ones that reach new
code, and mutates those: an automated adversary for the parser that reads
attacker-controlled bytes (`jsonrpc.Parse`, via `FuzzParse`). 30 s on every
change catches the "small" parsing tweak that panics on odd input. A crashing
input is saved under `internal/jsonrpc/testdata/fuzz/FuzzParse/`, and plain
`go test` replays it as a regression test from then on.

## (c) Exercise it by hand

Run these from the repo root.

**Install the tools and run everything CI runs:**

```bash
make tools            # installs govulncheck (pinned version) into $(go env GOPATH)/bin
golangci-lint --version   # should say 2.5.0; install steps are in the Makefile comment above `tools`
make ci               # vet, lint, test -race, fuzz (30 s), govulncheck
```

Cheap checks run first, so a vet error stops the run before the 30 s fuzz.

**Lint and vulnerability scan on their own:**

```bash
make lint
govulncheck ./...                 # symbol level: only reachable vulnerabilities
govulncheck -scan module ./...    # module level: everything in your dependencies
```

The difference between the two govulncheck runs is the noise a plain CVE
scanner would have given you. (`govulncheck -h` lists the other flags.)

**Which Go are you really using?**

```bash
go version                         # in the repo: the toolchain go.mod selected
GOTOOLCHAIN=local go version       # the Go you installed
go env GOTOOLCHAIN GOPROXY GOSUMDB
ls "$(go env GOMODCACHE)/golang.org/" | grep toolchain   # downloaded toolchains live here
```

If your Go is older than 1.25.14, the first command downloads go1.25.14; if
it's newer, nothing downloads. To watch a download anyway:

```bash
T="$(mktemp -d)"
GOMODCACHE="$T" GOTOOLCHAIN=go1.25.14 go version   # prints "go: downloading go1.25.14 (...)"
GOMODCACHE="$T" go clean -modcache                 # clean up
```

`GOTOOLCHAIN=go1.25.14` forces that exact version; see `go help toolchain`.

**Check dependencies and the binary:**

```bash
cat go.sum            # per module version: an h1: hash of its files and one of its go.mod (may not exist yet)
go mod verify         # re-hashes your local module cache: has anything on disk changed?
make build
go version -m bin/rover
```

`go version -m` prints what's embedded in the binary: the Go version, module
path, every dependency with its hash, and `vcs.revision` / `vcs.modified`
(`true` means it was built from a dirty tree). M14 builds release verification
on this.

## (d) Three attacks to try against it

Do these on your own machine, on a clean checkout or in a throwaway directory.

### Attack 1: tamper with a dependency

You need a module with a dependency, so make a throwaway one:

```bash
cd "$(mktemp -d)"
export GOMODCACHE="$PWD/modcache"    # a private module cache, so your real one stays clean
go mod init example.com/sumlab
printf 'package main\n\nimport (\n\t"fmt"\n\n\t"rsc.io/quote"\n)\n\nfunc main() { fmt.Println(quote.Go()) }\n' > main.go
go mod tidy
cat go.sum
go run .
cp go.sum go.sum.good
```

Now flip one character of the `rsc.io/quote v1.5.2 h1:` hash in `go.sum` and
build. You get `SECURITY ERROR ... checksum mismatch`. Try to talk Go out of it:

```bash
perl -pi -e 's/(quote v1\.5\.2 h1:)./${1}A/' go.sum   # or use an editor
go build .
GOFLAGS=-mod=mod go build .
GONOSUMDB=rsc.io go build .
GOSUMDB=off go build .
```

The three overrides all still refuse: `go.sum` always wins. These variables only control
whether a hash *not yet in go.sum* is checked against `sum.golang.org`. (Even
`go mod tidy` refuses to "fix" it.) So what would an attacker need? Restore
with `cp go.sum.good go.sum`, then:

1. Delete the `rsc.io/quote` lines from `go.sum` and run `go build .`
   (refused: `missing go.sum entry`).
2. Run `GONOSUMDB=rsc.io GOFLAGS=-mod=mod go build .`. It succeeds and
   re-adds the line, **without asking the checksum database**. That's TOFU with
   nobody to compare against. The attacker needs you to fetch from a poisoned
   source *and* to have checks turned off *and* a reviewer to accept the
   `go.sum` diff in a PR.

Finally, attack the cache instead of the download:

```bash
cp go.sum.good go.sum && go build .         # back to a clean, cached state
chmod -R u+w modcache/rsc.io/quote@v1.5.2   # the cache is read-only on purpose
perl -pi -e 's/Don.t communicate/PWNED/' modcache/rsc.io/quote@v1.5.2/quote.go
go run .                                    # prints PWNED: the build trusts the cache
go mod verify                               # catches it: "dir has been modified"
go clean -modcache                          # clean up the private cache
unset GOMODCACHE
```

`go build` trusts your local cache; `go mod verify` checks it. CI starts from
an empty cache every run, one reason to trust CI over your laptop.

### Attack 2: make the linters and race detector earn their keep

**Unchecked error.** In `internal/audit/logger.go`, inside `Open`, add this
line just after the `os.OpenFile` error check:

```go
	os.Chmod(path, 0o644)
```

Run `make lint`. `errcheck` flags the ignored error. Change it to
`_ = os.Chmod(path, 0o644)` and lint again: now `gosec` reports **G302**
(file permissions looser than `0600`). golangci-lint shows one issue per line,
so fixing one finding can reveal the next. If this shipped, who could read the
audit log, and what's in it? Then look at the `os.OpenFile` line above: if it
has a `//nolint:gosec // G304: ...` comment, remove it, lint, and decide
whether the reason given justifies the suppression.

**Data race.** In `internal/proxy/proxy.go`, in `observe`, delete the
`s.mu.Lock()` and `s.mu.Unlock()` around the line that writes
`s.pending[...]` for a request. Then run the tests two ways:

```bash
go test -race -skip TestBothDirectionsConcurrently ./internal/proxy/   # the older, one-direction tests
go test -race ./internal/proxy/                                        # everything
```

The first command **passes**. Those tests run one direction at a time, so
the racy accesses never overlap, and the race detector can only report
races that a test actually makes happen. The second command fails with
`WARNING: DATA RACE` and two stack traces, because
`TestBothDirectionsConcurrently` in `internal/proxy/race_test.go` pumps 500
requests and 500 responses through the same session from two goroutines.
Read that test: it's short, and it exists only to give `-race` something to
catch. Now run it without the flag:

```bash
go test -run TestBothDirectionsConcurrently ./internal/proxy/
```

You'll often get `fatal error: concurrent map writes`, but "often" isn't
"always": a race that doesn't crash today is still a race. Put the lock back,
rerun with `-race`, and see it pass. Undo everything with
`git checkout -- internal/`.

### Attack 3: unpin an action

In `.github/workflows/ci.yml`, change one `uses: actions/checkout@<sha> # v…`
line to `uses: actions/checkout@main`. Don't push it; reason it through instead:

1. Who can change what `main` points to? Anyone with push rights on
   `actions/checkout`, or anyone who steals one of their tokens.
2. On your next CI run, that person's code runs inside your job. Make a list of
   what it can reach: the checked-out source, the `GITHUB_TOKEN`, any secret
   passed to the job, the runner's network, and the test results it could fake
   to make a bad PR look green.
3. Now read the `permissions:` block at the top of the workflow. With only
   `contents: read`, can the token push a commit? Create a tag or release?
   Comment on a PR? Read a private repo of yours? (Check GitHub's docs page
   "Controlling permissions for GITHUB_TOKEN".) Then imagine the M14 release
   workflow, which will hold a signing key. How bad is the same attack there?

Stretch: check that a pin matches its comment. `git ls-remote
https://github.com/actions/checkout refs/tags/v7.0.1` prints the commit the
tag points to *today*. If it differs from the SHA in the workflow, either the
comment is wrong or the tag moved. Which would worry you more?

Undo with `git checkout -- .github/`.

## (e) Five explain-back questions

1. Walk through `go install github.com/DreadpiratePickles/rover/cmd/rover@v0.1.0`
   on a new machine. Where could an attacker interfere at each step, and which
   check catches them? Name one attack that *none* of the checks catch.
2. Rover's `go.mod` has both `go 1.25` and `toolchain go1.25.14`. Explain what
   each line does, what happens on a machine with Go 1.24 and on one with Go
   1.26, and why the patch number matters for a security tool.
3. Explain "trust on first use" using `go.sum` as the example. What's its weak
   point, how does `sum.golang.org` reduce it, and how will the same idea show
   up again in M4's tool pinning?
4. A teammate says: "We already run a CVE scanner, so govulncheck is
   redundant, and we write tests, so linters are redundant." Using examples
   from this lesson, explain what govulncheck does better than a plain CVE
   scanner, a bug a linter catches that tests probably wouldn't, and one
   threat that none of these tools would catch.
5. Retell the tj-actions/changed-files attack. Then explain, for Rover's
   workflow, what each of these does to limit the damage from a compromised
   action: SHA pinning, `permissions: contents: read`,
   `persist-credentials: false`, and using `pull_request` rather than
   `pull_request_target`.
