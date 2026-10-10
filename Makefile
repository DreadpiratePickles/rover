# Rover build, test and CI targets.
#
# `make ci` runs the same checks, in the same order, as .github/workflows/ci.yml.
# If you change one, change the other.

GOVULNCHECK_VERSION := v1.7.0
GOLANGCI_LINT_VERSION := v2.14.0

# Run every Go command with the toolchain go.mod pins, so `make ci` on a laptop
# with a newer or older Go gives the same answer as CI (govulncheck in
# particular reports standard-library findings for whatever toolchain runs it).
export GOTOOLCHAIN ?= $(shell awk '/^toolchain /{print $$2}' go.mod)

FUZZTIME := 30s

.PHONY: build test vet race fuzz eval lint vuln ci tools clean snapshot spike-auth

build:
	go build -o bin/rover ./cmd/rover
	go build -o bin/echo-server ./examples/echo-server
	go build -o bin/fake-remote ./examples/fake-remote

test: vet race

# The M9 spike: the macOS authentication dialog from a plain CLI and from a
# setsid'd daemon. Building it shows nothing; running it asks before it
# shows the dialog (see docs/lessons/M9-approvals.md).
spike-auth:
	go build -o bin/spike-auth ./cmd/spike-auth

# ./... skips testdata/, so the lab-only evil servers (build tag "lab") are
# vetted by path.
vet:
	go vet ./...
	go vet -tags lab ./testdata/servers/...

race:
	go test -race ./...

# Fails only if the fuzzer finds a crashing input (saved under
# internal/jsonrpc/testdata/fuzz/). Finding no new coverage is not a failure.
# One fuzz run per parser of attacker-controlled input (plan §0.5): the
# JSON-RPC classifier, the wrapper<->roverd frame parser, the audit-log
# verifier, the line reader under all of them, and (M2) tool-argument
# conversion, path normalisation, the policy decision and tools/list filtering,
# (M3) the policy.yaml compiler, (M4) the canonical JSON of tool pins, and
# (M5) the detection rules and roverd's rewriting of results, (M7) the
# client-config reader, which roverd's tamper watch runs on files an agent
# can write, (M9) the client's elicitation reply and the approval
# page's request handling, (M10) the secret detectors and the JSON
# redaction of results, and (M11) the bridge's SSE reader.
fuzz:
	go test ./internal/jsonrpc -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)
	go test ./internal/ipc -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)
	go test ./internal/audit -run='^$$' -fuzz=FuzzVerify -fuzztime=$(FUZZTIME)
	go test ./internal/framing -run='^$$' -fuzz=FuzzReadLine -fuzztime=$(FUZZTIME)
	go test ./internal/policy/convert -run='^$$' -fuzz=FuzzArgs -fuzztime=$(FUZZTIME)
	go test ./internal/policy/normalize -run='^$$' -fuzz=FuzzPath -fuzztime=$(FUZZTIME)
	go test ./internal/policy -run='^$$' -fuzz=FuzzDecide -fuzztime=$(FUZZTIME)
	go test ./internal/policy -run='^$$' -fuzz=FuzzFilterToolsList -fuzztime=$(FUZZTIME)
	go test ./internal/policy/yaml2cedar -run='^$$' -fuzz=FuzzCompile -fuzztime=$(FUZZTIME)
	go test ./internal/pin -run='^$$' -fuzz=FuzzCanonical -fuzztime=$(FUZZTIME)
	go test ./internal/detect -run='^$$' -fuzz=FuzzScan -fuzztime=$(FUZZTIME)
	go test ./internal/daemon -run='^$$' -fuzz=FuzzScanResult -fuzztime=$(FUZZTIME)
	go test ./internal/daemon -run='^$$' -fuzz=FuzzUnescape -fuzztime=$(FUZZTIME)
	go test ./internal/policy/propose -run='^$$' -fuzz=FuzzBuild -fuzztime=$(FUZZTIME)
	go test ./internal/clients -run='^$$' -fuzz=FuzzParseDoc -fuzztime=$(FUZZTIME)
	go test ./internal/approve -run='^$$' -fuzz=FuzzElicitReply -fuzztime=$(FUZZTIME)
	go test ./internal/approve/page -run='^$$' -fuzz=FuzzPageRequest -fuzztime=$(FUZZTIME)
	go test ./internal/dlp -run='^$$' -fuzz=FuzzFind -fuzztime=$(FUZZTIME)
	go test ./internal/dlp -run='^$$' -fuzz=FuzzRedact -fuzztime=$(FUZZTIME)
	go test ./internal/bridge -run='^$$' -fuzz=FuzzSSE -fuzztime=$(FUZZTIME)

# The detection gates (plan §6 M5) and the DLP gates (M10): recall, false
# positives and corpus size on testdata/corpus and testdata/corpus/dlp.
# Exits non-zero if a gate fails.
eval:
	go run ./cmd/rover eval --corpus testdata/corpus

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

# Order matters: cheap checks first, so a failure stops the run early.
ci:
	@$(MAKE) --no-print-directory vet
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory race
	@$(MAKE) --no-print-directory eval
	@$(MAKE) --no-print-directory fuzz
	@$(MAKE) --no-print-directory vuln

# Installs the pinned tools into $(go env GOPATH)/bin; make sure that is on PATH.
#
# golangci-lint $(GOLANGCI_LINT_VERSION) is not installed here: upstream advises
# against `go install` for it. Get the release binary instead, either from
#   https://github.com/golangci/golangci-lint/releases/tag/$(GOLANGCI_LINT_VERSION)
# (check it against golangci-lint-2.14.0-checksums.txt from the same page), or
# with the install script pinned to the same tag, which verifies the checksum:
#   curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh \
#     | sh -s -- -b "$$(go env GOPATH)/bin" $(GOLANGCI_LINT_VERSION)
tools:
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# A local release build (plan M7, v0.1.0): darwin and linux, arm64 and
# amd64, tar.gz archives and checksums in dist/. --snapshot never publishes
# or tags anything; Bobby tags releases.
snapshot:
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser is not installed. Install it (v2), then rerun make snapshot:"; \
		echo "  brew install goreleaser/tap/goreleaser"; \
		echo "  or: go install github.com/goreleaser/goreleaser/v2@latest"; \
		echo "  or: https://goreleaser.com/install/"; \
		exit 1; }
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
