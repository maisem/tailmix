//go:build linux

// Command linux-network-e2e exercises actual Linux TUN, Headscale, tailscale,
// dnsmasq, and checkout binaries in private Docker namespaces. It intentionally
// emits only fixed stage names and timings; never daemon output or identifiers.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type options struct {
	binaryDir string
	timeout   time.Duration
	cleanup   bool
}

func parseOptions(args []string) (options, bool, error) {
	fs := flag.NewFlagSet("linux-network-e2e", flag.ContinueOnError)
	// flag diagnostics can repeat caller-supplied values.
	fs.SetOutput(io.Discard)
	var opts options
	var seconds float64
	var removePrivate bool
	fs.StringVar(&opts.binaryDir, "binary-dir", "", "directory containing static Linux tailmix and tailmixd")
	fs.Float64Var(&seconds, "timeout", 720, "overall test deadline in seconds")
	fs.BoolVar(&opts.cleanup, "cleanup", false, "remove only exact TAILMIX_E2E_RUN_ID-labeled test resources")
	fs.BoolVar(&removePrivate, "remove-private", false, "internal: empty the exact private /cleanup mount")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return opts, false, failure("invalid arguments")
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds >= float64(math.MaxInt64)/float64(time.Second) {
		return opts, false, failure("timeout must be positive finite seconds")
	}
	opts.timeout = time.Duration(seconds * float64(time.Second))
	if opts.timeout <= 0 || (removePrivate && (len(args) != 1 || args[0] != "--remove-private")) {
		return opts, false, failure("invalid arguments")
	}
	return opts, removePrivate, nil
}

func runMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--serve-echo" || args[0] == "--echo-probe" || args[0] == "--socks-probe") {
		err := guarded(func() {
			if args[0] == "--serve-echo" {
				serveEcho()
			} else if args[0] == "--echo-probe" {
				echoProbe()
			} else {
				socksProbe()
			}
		})
		if err != nil {
			fmt.Fprintln(stdout, err)
			fmt.Fprintln(stderr, "linux-network: FAIL [SOCKS fixture]")
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: linux-network-e2e [--binary-dir DIR] [--timeout SECONDS] [--cleanup]")
		fmt.Fprintln(stdout, "Run real isolated Linux networking tests (default timeout: 720 seconds).")
		fmt.Fprintln(stdout, "--cleanup requires an explicit TAILMIX_E2E_RUN_ID.")
		return 0
	}
	opts, removePrivate, err := parseOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, "linux-network: FAIL [arguments]")
		return 1
	}
	if removePrivate {
		if removePrivateFiles() != nil {
			fmt.Fprintln(stderr, "linux-network: FAIL [private cleanup]")
			return 1
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if opts.cleanup {
		ctx, cancel := context.WithTimeout(ctx, min(opts.timeout, 60*time.Second))
		defer cancel()
		r := &rig{runner: runner{ctx}}
		if err := guarded(func() { cleanupRun(os.Getenv("TAILMIX_E2E_RUN_ID"), r.docker) }); err != nil {
			fmt.Fprintln(stderr, "linux-network: FAIL [labeled cleanup]")
			return 1
		}
		fmt.Fprintln(stdout, "linux-network: labeled cleanup verified")
		return 0
	}
	// Owner-only from creation, including state produced by child build tools.
	syscall.Umask(0o077)
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	var before snapshot
	var r *rig
	if guarded(func() {
		before = hostSnapshot(runner{ctx})
		r = newRig(ctx, opts, stdout)
	}) != nil {
		fmt.Fprintln(stderr, "linux-network: FAIL [host preflight]")
		return 1
	}
	failed := false
	if err := guarded(func() { r.setup(); r.tests(); r.socksTests() }); err != nil {
		fmt.Fprintf(stderr, "linux-network: FAIL [%s] %s\n", r.stage, err)
		failed = true
	}
	// Cancellation never poisons cleanup; it receives a fresh shared 60s budget,
	// including the final caller route/DNS invariance snapshot.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cleanupCancel()
	r.runner = runner{cleanupCtx}
	if err := guarded(func() {
		r.cleanup()
		require(hostSnapshot(r.runner) == before, "caller routes/DNS changed")
	}); err != nil {
		fmt.Fprintln(stderr, "linux-network: FAIL [cleanup/host invariance]")
		failed = true
	} else {
		fmt.Fprintln(stdout, "linux-network: cleanup and unchanged caller routes/DNS verified")
	}
	if failed {
		return 1
	}
	fmt.Fprintln(stdout, "linux-network: PASS")
	return 0
}

func main() { os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr)) }
