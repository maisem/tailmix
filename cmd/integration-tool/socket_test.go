package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func tcpListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func clientAddress(address net.Addr) (string, string) {
	host, port, _ := net.SplitHostPort(address.String())
	return host, port
}

func awaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("fixture did not publish readiness")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTCPRoundTrip(t *testing.T) {
	listener := tcpListener(t)
	readyPath := filepath.Join(t.TempDir(), "ready")
	done := make(chan error, 1)
	go func() { done <- serveTCP(listener, readyPath, 2, false, defaultSocketTimeouts) }()
	awaitFile(t, readyPath)
	host, port := clientAddress(listener.Addr())
	for _, payload := range []string{"first-payload", "second-payload"} {
		var stdout bytes.Buffer
		if err := run([]string{"tcp-client", host, port, payload}, &stdout); err != nil {
			t.Fatal(err)
		}
		if got := stdout.String(); got != "reply:"+payload {
			t.Fatalf("unexpected reply %q", got)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUDPRoundTrip(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	readyPath := filepath.Join(t.TempDir(), "ready")
	done := make(chan error, 1)
	go func() { done <- serveUDP(server, readyPath, defaultSocketTimeouts) }()
	awaitFile(t, readyPath)
	host, port := clientAddress(server.LocalAddr())
	var stdout bytes.Buffer
	if err := run([]string{"udp-client", host, port, "datagram"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "reply:datagram" {
		t.Fatalf("unexpected reply %q", stdout.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHeldTCPContinuation(t *testing.T) {
	listener := tcpListener(t)
	dir := t.TempDir()
	readyPath, first, proceed, result := filepath.Join(dir, "ready"), filepath.Join(dir, "first"), filepath.Join(dir, "continue"), filepath.Join(dir, "result")
	serverDone := make(chan error, 1)
	go func() { serverDone <- serveTCP(listener, readyPath, 1, true, defaultSocketTimeouts) }()
	awaitFile(t, readyPath)
	host, port := clientAddress(listener.Addr())
	clientDone := make(chan error, 1)
	go func() { clientDone <- run([]string{"hold-client", host, port, first, proceed, result}, io.Discard) }()
	awaitFile(t, first)
	data, err := os.ReadFile(first)
	if err != nil || string(data) != "reply:one\n" {
		t.Fatalf("invalid first reply, err=%v", err)
	}
	assertReadableFixture(t, first)
	if _, err := os.Stat(result); !os.IsNotExist(err) {
		t.Fatal("client continued before synchronization")
	}
	if err := os.WriteFile(proceed, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(result)
	if err != nil || string(data) != "reply:one\nreply:two\n" {
		t.Fatalf("invalid continuation replies, err=%v", err)
	}
	assertReadableFixture(t, result)
}

func assertReadableFixture(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Fixtures run under sudo in the namespaces; the unprivileged shell must
	// still be able to read their synchronization replies.
	if info.Mode().Perm()&0044 != 0044 {
		t.Fatal("fixture reply is not readable by the orchestration shell")
	}
}

func TestTCPClientRefused(t *testing.T) {
	listener := tcpListener(t)
	host, port := clientAddress(listener.Addr())
	listener.Close()
	err := run([]string{"tcp-client", host, port, "blocked"}, io.Discard)
	if !errors.Is(err, statusError(21)) {
		t.Fatalf("got %v, want connection-refused status 21", err)
	}
}

func TestClientTimeouts(t *testing.T) {
	deadlines := defaultSocketTimeouts
	deadlines.client = 20 * time.Millisecond
	t.Run("tcp", func(t *testing.T) {
		listener := tcpListener(t)
		accepted := make(chan *net.TCPConn, 1)
		go func() {
			conn, _ := listener.AcceptTCP()
			accepted <- conn
		}()
		host, port := clientAddress(listener.Addr())
		err := socketTool([]string{"tcp-client", host, port, "no-reply"}, io.Discard, deadlines)
		conn := <-accepted
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, statusError(20)) {
			t.Fatalf("got %v, want timeout status 20", err)
		}
	})
	t.Run("udp", func(t *testing.T) {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		host, port := clientAddress(server.LocalAddr())
		err = socketTool([]string{"udp-client", host, port, "no-reply"}, io.Discard, deadlines)
		if !errors.Is(err, statusError(20)) {
			t.Fatalf("got %v, want timeout status 20", err)
		}
	})
}

func TestClientErrorOther(t *testing.T) {
	if got := clientError(syscall.ENETUNREACH); !errors.Is(got, statusError(22)) {
		t.Fatalf("got %v, want network error status 22", got)
	}
}

func TestHoldClientSynchronizationTimeout(t *testing.T) {
	listener := tcpListener(t)
	dir := t.TempDir()
	deadlines := defaultSocketTimeouts
	deadlines.hold = 30 * time.Millisecond
	deadlines.poll = time.Millisecond
	done := make(chan error, 1)
	go func() { done <- serveTCP(listener, filepath.Join(dir, "ready"), 1, true, defaultSocketTimeouts) }()
	host, port := clientAddress(listener.Addr())
	err := socketTool([]string{"hold-client", host, port, filepath.Join(dir, "first"), filepath.Join(dir, "absent"), filepath.Join(dir, "result")}, io.Discard, deadlines)
	if !errors.Is(err, statusError(31)) {
		t.Fatalf("got %v, want synchronization timeout status 31", err)
	}
	if err := <-done; !errors.Is(err, statusError(30)) {
		t.Fatalf("got %v, want unexpected EOF status 30", err)
	}
}

func TestParsePort(t *testing.T) {
	for _, port := range []string{"0", "12345", "65535"} {
		if got := parsePort(port); strconv.Itoa(got) != port {
			t.Fatalf("parsePort(%q) = %d", port, got)
		}
	}
	for _, port := range []string{"bad", "-1", "65536"} {
		if parsePort(port) != -1 {
			t.Fatal("invalid port accepted")
		}
	}
}
