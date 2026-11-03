// Command fake-remote runs the test doubles of `rover bridge` (M11) for
// trying it by hand: a remote MCP server (Streamable HTTP, sessions, JSON
// or SSE) and an OAuth 2.1 authorization server that approves every login
// at once. Both listen on 127.0.0.1 over TLS with throwaway certificates,
// written as PEM to -ca so config.yaml's bridges.<name>.ca_file can trust
// them. Nothing here is secure; never point it at real credentials.
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"

	"github.com/DreadpiratePickles/rover/internal/bridge/bridgetest"
)

func main() {
	caPath := flag.String("ca", "fake-remote-ca.pem", "where to write the servers' certificates (PEM)")
	sse := flag.Bool("sse", false, "answer requests with text/event-stream")
	noAuth := flag.Bool("no-auth", false, "do not require a bearer token")
	asHTTP := flag.Bool("as-http", false, "serve the authorization server over plain http on 127.0.0.1 (so a real browser needs no certificate)")
	flag.Parse()

	as := &bridgetest.AS{}
	var asSrv *httptest.Server
	if *asHTTP {
		asSrv = httptest.NewServer(as)
	} else {
		asSrv = httptest.NewTLSServer(as)
	}
	defer asSrv.Close()
	as.Issuer = asSrv.URL

	remote := &bridgetest.Remote{SSE: *sse, GET: true, AuthServer: asSrv.URL}
	rSrv := httptest.NewTLSServer(remote)
	defer rSrv.Close()
	remote.Base = rSrv.URL
	if !*noAuth {
		remote.Check = func(tok string) bool { return as.Valid(tok, remote.URL()) }
	}

	var buf []byte
	for _, srv := range []*httptest.Server{asSrv, rSrv} {
		if c := srv.Certificate(); c != nil {
			buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}
	if err := os.WriteFile(*caPath, buf, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "fake-remote:", err)
		os.Exit(1)
	}
	fmt.Printf("remote MCP endpoint  %s\nauthorization server %s\ncertificates         %s\n", remote.URL(), as.Issuer, *caPath)
	fmt.Printf("\nconfig.yaml:\nbridges:\n  fake:\n    url: %s\n    pq_required: true\n    ca_file: %s\n", remote.URL(), *caPath)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
