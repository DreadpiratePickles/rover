# Rover build, test and CI targets.
#
# `make ci` runs the same checks, in the same order, as .github/workflows/ci.yml.
# If you change one, change the other.

GOVULNCHECK_VERSION := v1.7.0
GOLANGCI_LINT_VERSION := v2.5.0

# Run every Go command with the toolchain go.mod pins, so `make ci` on a laptop
# with a newer or older Go gives the same answer as CI (govulncheck in
# particular reports standard-library findings for whatever toolchain runs it).
export GOTOOLCHAIN ?= $(shell awk '/^toolchain /{print $$2}' go.mod)

FUZZTIME := 30s

.PHONY: build test vet race fuzz lint vuln ci tools clean

build:
	go build -o bin/rover ./cmd/rover
	go build -o bin/echo-server ./examples/echo-server

test: vet race

vet:
	go vet ./...

race:
	go test -race ./...

# Fails only if the fuzzer finds a crashing input (saved under
# internal/jsonrpc/testdata/fuzz/). Finding no new coverage is not a failure.
# One fuzz run per parser of attacker-controlled input (plan §0.5): the
# JSON-RPC classifier and the wrapper<->roverd frame parser.
fuzz:
	go test ./internal/jsonrpc -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)
	go test ./internal/ipc -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

# Order matters: cheap checks first, so a failure stops the run early.
ci:
	@$(MAKE) --no-print-directory vet
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory race
	@$(MAKE) --no-print-directory fuzz
	@$(MAKE) --no-print-directory vuln

# Installs the pinned tools into $(go env GOPATH)/bin; make sure that is on PATH.
#
# golangci-lint $(GOLANGCI_LINT_VERSION) is not installed here: upstream advises
# against `go install` for it. Get the release binary instead, either from
#   https://github.com/golangci/golangci-lint/releases/tag/$(GOLANGCI_LINT_VERSION)
# (check it against golangci-lint-2.5.0-checksums.txt from the same page), or
# with the install script pinned to the same tag, which verifies the checksum:
#   curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh \
#     | sh -s -- -b "$$(go env GOPATH)/bin" $(GOLANGCI_LINT_VERSION)
tools:
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean:
	rm -rf bin
