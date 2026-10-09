# Rover build, test and CI targets.
#
# `make ci` runs the same checks, in the same order, as .github/workflows/ci.yml.
# If you change one, change the other.

GOVULNCHECK_VERSION := v1.8.0
GOLANGCI_LINT_VERSION := v2.5.0

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
fuzz:
	go test ./internal/jsonrpc -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)

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
