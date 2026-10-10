package ipc

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/framing"
)

// fakeDaemon accepts one connection, answers the hello and returns the
// connection so the test can push frames.
func fakeDaemon(t *testing.T) (string, <-chan net.Conn) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rover-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if _, err := framing.ReadLine(bufio.NewReader(c), MaxFrame); err != nil {
			return
		}
		line, _ := Encode(Frame{Type: TypeWelcome, SessionID: "s1"})
		_, _ = c.Write(line)
		conns <- c
	}()
	return sock, conns
}

func TestInjectFrameReachesTheHandler(t *testing.T) {
	// Arrange
	sock, conns := fakeDaemon(t)
	c, err := Dial(sock, Hello{WrapperPID: 1, ClientPID: 1, ServerName: "x", Transport: "stdio"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got := make(chan []byte, 1)
	c.SetInjectHandler(func(raw []byte) { got <- raw })
	srv := <-conns

	// Act
	line, _ := Encode(Frame{Type: TypeInject, Raw: []byte(`{"jsonrpc":"2.0","id":"rover-1","method":"elicitation/create"}`)})
	if _, err := srv.Write(line); err != nil {
		t.Fatal(err)
	}

	// Assert
	select {
	case raw := <-got:
		if string(raw) != `{"jsonrpc":"2.0","id":"rover-1","method":"elicitation/create"}` {
			t.Fatalf("raw changed: %s", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inject never reached the handler")
	}
}
