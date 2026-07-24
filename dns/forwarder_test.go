package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"tailscale.com/types/dnstype"
)

type networkDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (d *networkDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestForwarderDoHUsesProfileDialerAndBootstrapResolution(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(append([]byte("response:"), body...))
	})}
	go server.Serve(listener)
	defer server.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialer := &networkDialer{}
	forwarder := &Forwarder{dialer: dialer}
	got, err := forwarder.exchangeHTTP(context.Background(), &dnstype.Resolver{
		Addr:                "http://resolver.invalid:" + port + "/dns-query",
		BootstrapResolution: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "response:query" {
		t.Fatalf("response = %q", got)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.addrs) == 0 || !strings.HasPrefix(dialer.addrs[0], "127.0.0.1:") {
		t.Fatalf("profile dial addresses = %q", dialer.addrs)
	}
}
