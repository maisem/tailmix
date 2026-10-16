package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maisem/tailmix/wireguardcfg"
)

func TestKeygen(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"keygen"}, &stdout); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("generated %d key pairs", len(lines))
	}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatal("invalid key pair format")
		}
		private, err := wireguardcfg.ParseKey(parts[0])
		if err != nil {
			t.Fatal("invalid generated private key")
		}
		public, err := private.Public()
		if err != nil || public.String() != parts[1] {
			t.Fatal("generated public key does not match")
		}
	}
	if lines[0] == lines[1] {
		t.Fatal("generated identical key pairs")
	}
}

func TestEffectiveAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	for _, test := range []struct {
		json, want string
	}{{`{"peers":[{"effectiveAddresses":["192.0.2.1"]}]}`, "192.0.2.1\n"}, {`{}`, ""}, {`{"peers":[]}`, ""}, {`{"peers":[{"effectiveAddresses":[]}]}`, ""}, {`{"peers":[{"effectiveAddresses":[""]}]}`, ""}, {`not-json`, ""}} {
		if err := os.WriteFile(path, []byte(test.json), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		err := run([]string{"effective-address", path}, &stdout)
		if (err != nil) != (test.want == "") || stdout.String() != test.want {
			t.Fatalf("got output=%q err=%v", stdout.String(), err)
		}
	}
}

func writeReports(t *testing.T, dir string) {
	t.Helper()
	for _, concurrency := range []int{1, 4, 8} {
		for _, direction := range []string{"normal", "reverse"} {
			for run := 1; run <= 3; run++ {
				bps := []int{900000000, 1100000000, 1000000000}[run-1]
				if direction == "reverse" {
					bps = 2000000000
				}
				data := fmt.Sprintf(`{"end":{"sum_received":{"bits_per_second":%d},"sum_sent":{"retransmits":%d}}}`, bps, run)
				path := filepath.Join(dir, fmt.Sprintf("p%d-%s-%d.json", concurrency, direction, run))
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestBenchmarkReport(t *testing.T) {
	dir := t.TempDir()
	writeReports(t, dir)
	var stdout bytes.Buffer
	if err := run([]string{"benchmark-report", dir}, &stdout); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"P1 normal runs:\n  run 1: 0.900 Gbit/s, retransmits=1\n",
		"summary: median=1.000 Gbit/s min=0.900 Gbit/s max=1.100 Gbit/s unstable=yes\n",
		"summary: median=2.000 Gbit/s min=2.000 Gbit/s max=2.000 Gbit/s unstable=no\n",
		"P4 normal runs:", "P8 reverse runs:",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing report fragment %q", want)
		}
	}
}

func TestBenchmarkReportInvalid(t *testing.T) {
	for _, data := range []string{`not-json`, `{"error":"failed"}`, `{}`, `{"end":{"sum_received":{}}}`, `{"end":{"sum_received":{"bits_per_second":-1}}}`} {
		t.Run(data, func(t *testing.T) {
			dir := t.TempDir()
			writeReports(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "p1-normal-1.json"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"benchmark-report", dir}, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted invalid benchmark result")
			}
		})
	}
}

func TestRunInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"keygen", "extra"}, {"effective-address"}, {"benchmark-report"}, {"tcp-client"}, {"udp-server", "invalid", "unused"}, {"tcp-server", "invalid", "unused", "1"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid arguments %q", args)
		}
	}
}
