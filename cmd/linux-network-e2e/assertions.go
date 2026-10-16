//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type tailNode struct{ TailscaleIPs []string }
type tailStatus struct {
	BackendState string
	Self         tailNode
	Peer         map[string]tailNode
}

type savedState struct {
	SyntheticPool string
	NatIP         string
	NatIPV6       string
	DNSIP         string
	Leases        []struct{ CanonicalIP, EffectiveIP string }
}

var (
	noerrorStatus  = regexp.MustCompile(`status: NOERROR\b`)
	servfailStatus = regexp.MustCompile(`status: SERVFAIL\b`)
	authoritative  = regexp.MustCompile(`flags:[^;]*\baa\b`)
	privateAnswer  = regexp.MustCompile(`(?m)^service\.corp\.test\.\s+60\s+IN\s+A\s+192\.168\.50\.42\s*$`)
)

func answer(res result, expected string) error {
	status := noerrorStatus
	if expected == "SERVFAIL" {
		status = servfailStatus
	} else if expected != "NOERROR" {
		return failure("DNS response status")
	}
	if res.code != 0 || !status.MatchString(res.stdout) {
		return failure("DNS response status")
	}
	if expected == "NOERROR" {
		if !authoritative.MatchString(res.stdout) {
			return failure("authoritative private DNS")
		}
		if !privateAnswer.MatchString(res.stdout) {
			return failure("private DNS answer/TTL")
		}
	}
	return nil
}

func digArgs(tcp bool) []string {
	args := []string{"dig", "@100.127.0.53", "service.corp.test", "A", "+time=6", "+tries=1", "+nocookie"}
	if tcp {
		args = append(args, "+tcp")
	}
	return args
}

func sameIPs(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

func (r *rig) tests() {
	r.announce("kernel route and dual-stack ICMP regression assertions")
	ts := decode[tailStatus](r.c("ts", "--profile", "work", "status", "--json"))
	require(ts.BackendState == "Running", "profile backend state")
	canonical := ts.Self.TailscaleIPs
	require(contains(canonical, "100.64.0.2"), "fresh client allocator")
	require(len(ts.Peer) == 1, "actual peer status")
	var peer tailNode
	for _, p := range ts.Peer {
		peer = p
	}
	require(sameIPs(r.peerIPs, peer.TailscaleIPs), "actual peer status")
	state := decode[savedState](r.e("client", "cat", "/private/state.json"))
	nat, err := netip.ParseAddr(state.NatIP)
	require(err == nil && state.SyntheticPool == "100.127.0.0/16" &&
		netip.MustParsePrefix("100.127.0.0/16").Contains(nat) && state.DNSIP == "100.127.0.53",
		"default synthetic root/NAT/DNS")
	for i, ips := range [][]string{canonical, peer.TailscaleIPs} {
		for _, family := range []int{4, 6} {
			real := ""
			for _, text := range ips {
				addr, err := netip.ParseAddr(text)
				require(err == nil, "canonical address discovery")
				if (family == 4 && addr.Is4()) || (family == 6 && addr.Is6()) {
					require(real == "", "canonical address discovery")
					real = text
				}
			}
			require(real != "", "dual-stack canonical address discovery")
			var effective []string
			if i == 0 {
				effective = []string{state.NatIP}
				if family == 6 {
					effective = []string{state.NatIPV6}
				}
			} else {
				for _, lease := range state.Leases {
					if lease.CanonicalIP == real {
						effective = append(effective, lease.EffectiveIP)
					}
				}
			}
			require(len(effective) == 1, "effective address discovery")
			addr, err := netip.ParseAddr(effective[0])
			require(err == nil && ((family == 4 && addr.Is4()) || (family == 6 && addr.Is6())), "effective address family")
			// Warm only initial WireGuard establishment. The two-packet
			// regression assertion itself is strict and is never retried.
			familyFlag := "-" + strconv.Itoa(family)
			r.poll(12*time.Second, func() bool {
				return r.ex(false, 3*time.Second, "client", "ping", familyFlag, "-n", "-c", "1", "-W", "1", effective[0]).code == 0
			})
			r.e("client", "ping", familyFlag, "-n", "-c", "2", "-W", "2", effective[0])
		}
	}
	r.announce("private corporate UDP and TCP DNS")
	r.c("dns", "routes", "bind", "--profile", "work", "corp.test")
	r.answers()
	r.announce("bounded resolver outage and recovery")
	if err := guarded(func() {
		r.pause("STOP")
		for _, tcp := range []bool{false, true} {
			started := time.Now()
			res := r.ex(true, 8*time.Second, "client", digArgs(tcp)...)
			elapsed := time.Since(started)
			require(answer(res, "SERVFAIL") == nil, "DNS outage response")
			require(elapsed <= 4500*time.Millisecond, "DNS outage deadline")
			transport := "UDP"
			if tcp {
				transport = "TCP"
			}
			fmt.Fprintf(r.out, "linux-network: outage %s %.3fs\n", transport, elapsed.Seconds())
		}
	}); err != nil {
		// The outer cleanup also resumes dnsmasq when cancellation prevents
		// this call; no canceled context is reused for cleanup.
		_ = guarded(func() { r.pause("CONT") })
		panic(err)
	}
	r.pause("CONT")
	r.answers()
	r.announce("two accepted queries across two policy generations")
	var q0, q1 *pending
	if err := guarded(func() {
		r.pause("STOP")
		before := r.recvq()
		q0 = r.launch(digArgs(true))
		r.poll(1500*time.Millisecond, func() bool { return r.recvq() > before })
		r.mutate("service.corp.test")
		before = r.recvq()
		q1 = r.launch(digArgs(false))
		r.poll(1500*time.Millisecond, func() bool { return r.recvq() > before })
		r.mutate("unused.corp.test")
	}); err != nil {
		_ = guarded(func() { r.pause("CONT") })
		panic(err)
	}
	r.pause("CONT")
	for _, q := range []*pending{q0, q1} {
		res := must(q.wait(r.ctx))
		require(answer(res, "NOERROR") == nil, "accepted DNS response")
		require(time.Since(q.started) < 4500*time.Millisecond, "accepted query deadline")
	}
	require(answer(r.e("client", digArgs(true)...), "NOERROR") == nil, "final DNS response")
}

func (r *rig) answers() {
	for _, tcp := range []bool{false, true} {
		if err := answer(r.e("client", digArgs(tcp)...), "NOERROR"); err != nil {
			panic(err)
		}
	}
}

func (r *rig) pause(sig string) {
	require(sig == "STOP" || sig == "CONT", "invalid resolver signal")
	r.e("peer", "sh", "-c", "kill -"+sig+" $(cat /private/dnsmasq.pid)")
	r.paused = sig == "STOP"
}

func recvQueue(text string) (int, error) {
	total := 0
	// ss UDP columns: state recv-q send-q local-address:port peer-address:port.
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasSuffix(fields[3], ":53") {
			continue
		}
		count, err := strconv.Atoi(fields[1])
		if err != nil || count < 0 {
			return 0, failure("invalid resolver queue")
		}
		total += count
	}
	return total, nil
}

func (r *rig) recvq() int {
	return must(recvQueue(r.e("peer", "ss", "-H", "-u", "-l", "-n").stdout))
}

func (r *rig) launch(args []string) *pending {
	p := must(r.runner.launch(command{
		argv: append([]string{"docker", "exec", r.names["client"]}, args...), timeout: 8 * time.Second,
	}))
	r.pending = append(r.pending, p)
	return p
}

func (r *rig) mutate(domain string) {
	started := time.Now()
	r.cli(true, 1400*time.Millisecond, "dns", "routes", "bind", "--profile", "work", domain)
	require(time.Since(started) <= 1400*time.Millisecond, "policy mutation blocked")
}
