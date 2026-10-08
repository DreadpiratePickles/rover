.PHONY: build test fuzz clean

build:
	go build -o bin/rover-gate ./cmd/rover-gate
	go build -o bin/echo-server ./examples/echo-server

test:
	go vet ./...
	go test -race ./...

fuzz:
	go test ./internal/jsonrpc -run=^$$ -fuzz=FuzzParse -fuzztime=30s

clean:
	rm -rf bin
