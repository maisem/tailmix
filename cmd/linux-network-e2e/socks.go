//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type socksCase struct {
	Target  string
	Allowed bool
}

// serveEcho runs inside the existing kernel peer, not in the proxy process.
// Both address families must work; a missing IPv6 listener is a test failure.
func serveEcho() {
	ln := must(net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6unspecified, Port: 18080}))
	defer ln.Close()
	require(ln.SetDeadline(time.Now().Add(5*time.Minute)) == nil, "echo listener deadline")
	for {
		conn := must(ln.AcceptTCP())
		go func() {
			defer conn.Close()
			if conn.SetDeadline(time.Now().Add(10*time.Second)) == nil {
				_, _ = io.Copy(conn, conn)
			}
		}()
	}
}

func socksProbe() {
	var cases []socksCase
	data := must(os.ReadFile("/private/socks-cases.json"))
	require(json.Unmarshal(data, &cases) == nil && len(cases) > 0, "SOCKS probe cases")
	dialer := must(proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 5 * time.Second}))
	contextDialer, ok := dialer.(proxy.ContextDialer)
	require(ok, "SOCKS context dialer")
	for _, test := range cases {
		if err := probeConnection(contextDialer, test); err != nil {
			panic(err)
		}
	}
}

func echoProbe() {
	for _, host := range []string{"127.0.0.1", "::1"} {
		if err := probeConnection(&net.Dialer{Timeout: 5 * time.Second},
			socksCase{net.JoinHostPort(host, "18080"), true}); err != nil {
			panic(err)
		}
	}
}

func probeConnection(dialer proxy.ContextDialer, test socksCase) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", test.Target)
	if !test.Allowed {
		if conn != nil {
			conn.Close()
		}
		if err == nil || ctx.Err() != nil {
			return failure("SOCKS rejection")
		}
		return nil
	}
	if err != nil {
		return failure("SOCKS connect")
	}
	defer conn.Close()
	if conn.SetDeadline(time.Now().Add(6*time.Second)) != nil {
		return failure("SOCKS stream deadline")
	}
	payload := bytes.Repeat([]byte("tailmix-socks-payload\x00"), 4096)
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, bytes.NewReader(payload))
		written <- err
	}()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return failure("SOCKS stream read")
	}
	if err := <-written; err != nil || !bytes.Equal(response, payload) {
		return failure("SOCKS stream payload")
	}
	return nil
}

func (r *rig) socksTests() {
	r.announce("real userspace SOCKS proxy without TUN or NET_ADMIN")
	// Preserve the real registration/state, but replace the namespace so no
	// leftover TUN route or kernel capability can make a userspace test pass.
	r.e("client", "sh", "-c", "kill -TERM $(cat /private/app.pid)")
	r.poll(8*time.Second, func() bool {
		return r.ex(false, 2*time.Second, "client", "sh", "-c",
			"kill -0 $(cat /private/app.pid) 2>/dev/null").code != 0
	})
	r.d("rm", "-f", r.names["client"])
	r.clientStarted = false
	for _, role := range []string{"peer", "client"} {
		require(copyCleanupHelper(filepath.Join(r.tmp, role, "socket-helper")) == nil, "socket helper copy")
	}
	r.d("exec", "-d", r.names["peer"], "/private/socket-helper", "--serve-echo")
	r.poll(5*time.Second, func() bool {
		return strings.Contains(r.e("peer", "ss", "-H", "-l", "-t", "-n").stdout, ":18080")
	})
	r.ex(true, 20*time.Second, "peer", "/private/socket-helper", "--echo-probe")
	r.start("client", r.image, false, []string{
		"--env-file", filepath.Join(r.tmp, "client", "env"),
		"--mount", "type=bind,src=" + r.bind(r.binaryDir) + ",dst=/checkout,readonly",
		// A host-resolver fallback would succeed for these names even when
		// the profile resolver rejects them or is unavailable.
		"--add-host=missing.corp.test:100.64.0.1",
		"--add-host=outage.corp.test:100.64.0.1",
		"--add-host=proxy.corp.test:127.0.0.1",
	}, nil)
	r.e("client", "test", "!", "-e", "/dev/net/tun")
	r.e("client", "ln", "-s", "/checkout/tailmix", "/bin/tailmix")
	r.d("exec", "-d", r.names["client"], "sh", "-c",
		"echo $$ > /private/app.pid; exec /checkout/tailmixd --mode=socks --socks=127.0.0.1:1080 "+
			"--auto-update=false --state=/private/state.json --socket-dir=/private/sockets "+
			"--profile=id=work,dir=/private/work,hostname=client,auth-key-env=TEST_AUTHKEY "+
			"> /private/socks-daemon.log 2>&1")
	r.clientStarted = true
	r.poll(60*time.Second, r.ready)
	r.announce("SOCKS direct path readiness")
	r.poll(12*time.Second, func() bool {
		return r.cli(false, 3*time.Second, "ts", "--profile", "work", "ping",
			"--tsmp", "--c=1", "--timeout=1s", "--until-direct=false", r.peerIPs[0]).code == 0
	})
	state := decode[savedState](r.e("client", "cat", "/private/state.json"))
	var effective []string
	for _, family := range []int{4, 6} {
		target := ""
		for _, lease := range state.Leases {
			if !contains(r.peerIPs, lease.CanonicalIP) {
				continue
			}
			ip, err := netip.ParseAddr(lease.EffectiveIP)
			require(err == nil, "SOCKS effective address")
			if (family == 4 && ip.Is4()) || (family == 6 && ip.Is6()) {
				require(target == "", "SOCKS effective address ambiguity")
				target = ip.String()
			}
		}
		require(target != "", "SOCKS dual-stack effective addresses")
		effective = append(effective, target)
	}
	check := func(stage, target string, allowed bool) {
		r.announce("SOCKS " + stage)
		data := must(json.Marshal([]socksCase{{target, allowed}}))
		require(privateWrite(filepath.Join(r.tmp, "client", "socks-cases.json"),
			string(data)) == nil, "SOCKS probe configuration")
		result := r.ex(false, 20*time.Second, "client", "/private/socket-helper", "--socks-probe")
		if result.code != 0 {
			// Only fixed fixture categories may cross the subprocess boundary.
			switch category := strings.TrimSpace(result.stdout); category {
			case "SOCKS rejection", "SOCKS connect", "SOCKS stream deadline",
				"SOCKS stream read", "SOCKS stream payload", "SOCKS context dialer",
				"SOCKS probe cases":
				panic(failure(category))
			default:
				panic(failure("SOCKS probe failed"))
			}
		}
	}
	check("effective IPv4 stream", net.JoinHostPort(effective[0], "18080"), true)
	check("effective IPv6 stream", net.JoinHostPort(effective[1], "18080"), true)
	check("MagicDNS stream", "resolver.isolated.test:18080", true)
	check("normalized MagicDNS stream", "RESOLVER.ISOLATED.TEST.:18080", true)
	check("private dual-stack DNS stream", "proxy.corp.test:18080", true)
	check("private IPv4-only DNS stream", "proxy4.corp.test:18080", true)
	check("private IPv6-only DNS stream", "proxy6.corp.test:18080", true)
	check("private DNS alias stream", "alias.corp.test:18080", true)
	check("private NXDOMAIN without host fallback", "missing.corp.test:18080", false)
	if err := guarded(func() {
		r.pause("STOP")
		check("private resolver outage without host fallback", "outage.corp.test:18080", false)
	}); err != nil {
		r.pause("CONT")
		panic(err)
	}
	r.pause("CONT")
	check("private resolver recovery", "outage.corp.test:18080", true)

	for _, ip := range r.peerIPs {
		check("canonical address refusal", net.JoinHostPort(ip, "18080"), false)
	}
	check("short name refusal", "resolver:18080", false)
	check("unbound loopback refusal", "127.0.0.1:1080", false)
	check("refused backend", net.JoinHostPort(effective[0], "18081"), false)
	// A final allowed request proves denials did not kill the listener.
	check("recovery after refusal", net.JoinHostPort(effective[0], "18080"), true)
}
