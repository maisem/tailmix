//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDaemonPath(t *testing.T) {
	shared := t.TempDir()
	mounts := []mount{{"bind", "/daemon/work", shared}, {"bind", "/daemon/temp", filepath.Join(shared, "temp")}, {"volume", "/hidden", filepath.Join(shared, "hidden")}}
	for _, tt := range []struct{ path, want string }{
		{filepath.Join(shared, "bin"), "/daemon/work/bin"},
		{filepath.Join(shared, "temp", "state"), "/daemon/temp/state"},
		{shared + "-other/bin", ""},
		{filepath.Join(shared, "hidden", "state"), ""},
	} {
		got, err := daemonPath(tt.path, mounts)
		if (err != nil) != (tt.want == "") || got != tt.want {
			t.Fatalf("mapping: got %q, %v; want %q", got, err, tt.want)
		}
	}
	if _, err := daemonPath(shared, []mount{{"bind", "relative", shared}}); err == nil {
		t.Fatal("accepted relative daemon path")
	}
	if _, err := daemonPath(shared, []mount{}); err == nil {
		t.Fatal("accepted unshared path")
	}
	if got, err := daemonPath(shared, nil); err != nil || got != shared {
		t.Fatal("direct caller mapping failed")
	}
}

func TestResolveSymlinksBeforeDotDot(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{shared, filepath.Join(outside, "sub")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{filepath.Join(outside, "sub"), filepath.Join(outside, "missing")} {
		link := filepath.Join(shared, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		raw := link + "/../bin"
		got, err := resolvePath(raw)
		if err != nil || got != filepath.Join(outside, "bin") {
			t.Fatalf("symlink parent resolution failed: %v", err)
		}
		if _, err := daemonPath(raw, []mount{{"bind", "/daemon/shared", shared}}); err == nil {
			t.Fatal("symlink parent escaped bind validation")
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnContainerMounts(t *testing.T) {
	id := strings.Repeat("a", 64)
	host := id[:12]
	info := []map[string]any{{"Id": id, "Config": map[string]string{"Hostname": host}, "Mounts": []mount{{"bind", "/daemon/work", "/work"}}}}
	data, _ := json.Marshal(info)
	calls := []string{}
	inspect := func(name string) result {
		calls = append(calls, name)
		if name != host {
			return result{code: 1}
		}
		return result{stdout: string(data)}
	}
	got, err := ownContainerMounts(inspect, "unavailable", host)
	if err != nil || len(got) != 1 || len(calls) != 2 {
		t.Fatal("validated hostname fallback failed")
	}
	for _, payload := range []string{"not-json", `[]`, `[{}]`} {
		if _, err := ownContainerMounts(func(string) result { return result{stdout: payload} }, host, host); err == nil {
			t.Fatal("accepted invalid inspect response")
		}
	}
	if _, err := ownContainerMounts(func(string) result { t.Fatal("inspected invalid identity"); return result{} }, "--option", "bad/name"); err == nil {
		t.Fatal("accepted invalid identity")
	}
}

func TestLifecycleAndCleanupOwnership(t *testing.T) {
	for _, id := range []string{"", "bad/name", "bad\nname", strings.Repeat("a", 129)} {
		if _, err := lifecycleLabels(id, true); err == nil {
			t.Fatal("accepted invalid run identity")
		}
	}
	if labels, err := lifecycleLabels("", false); err != nil || len(labels) != 0 {
		t.Fatal("optional label failed")
	}
	prefix := "tailmix-e2e-" + strings.Repeat("a", 32) + "-"
	removed := []string{}
	docker := func(_ bool, _ time.Duration, args ...string) result {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--filter") {
			if !strings.Contains(joined, "label="+runLabel+"=unit-run") {
				t.Fatal("cleanup used broad resource selection")
			}
			switch args[0] {
			case "ps":
				return result{stdout: prefix + "client\nforeign-job\n" + prefix + "client\n"}
			case "network":
				return result{stdout: prefix + "net\nforeign-network\n"}
			case "image":
				return result{stdout: prefix + "tools:latest\nforeign:latest\n"}
			}
		}
		if args[0] != "info" {
			removed = append(removed, args[len(args)-1])
		}
		return result{}
	}
	cleanupRun("unit-run", docker)
	if want := []string{prefix + "client", prefix + "net", prefix + "tools:latest"}; !reflect.DeepEqual(removed, want) {
		t.Fatal("cleanup removed unexpected resources")
	}
	called := false
	if guarded(func() { cleanupRun("", func(bool, time.Duration, ...string) result { called = true; return result{} }) }) == nil || called {
		t.Fatal("cleanup without identity accessed Docker")
	}
}

func TestPrivateWriteAndCleanupMount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := privateWrite(path, "new"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private file permissions")
	}
	if !exactCleanupMount("1 0 0:1 / /cleanup rw - ext4 /dev/test rw") || exactCleanupMount("1 0 0:1 / /cleanup-other rw - ext4 /dev/test rw") {
		t.Fatal("cleanup requires exact mount")
	}

}

func TestDNSAnswers(t *testing.T) {
	good := "status: NOERROR, flags: qr aa rd;\nservice.corp.test. 60 IN A 192.168.50.42\n"
	if err := answer(result{stdout: good}, "NOERROR"); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{strings.ReplaceAll(good, " aa ", " "), strings.ReplaceAll(good, "60 IN", "59 IN"), strings.ReplaceAll(good, "NOERROR", "SERVFAIL")} {
		if answer(result{stdout: text}, "NOERROR") == nil {
			t.Fatal("accepted incorrect private answer")
		}
	}
	if answer(result{code: 1, stdout: good}, "NOERROR") == nil {
		t.Fatal("accepted failed dig")
	}
	if answer(result{stdout: "status: SERVFAIL,"}, "SERVFAIL") != nil {
		t.Fatal("rejected SERVFAIL")
	}
}

func TestStatusAndQueue(t *testing.T) {
	running := `{"profiles":[{"backendState":"Running","peerCount":1}],"ipRoutes":{},"exitNodes":{}}`
	if ready, err := readyStatus(running); !ready || err != nil {
		t.Fatal("running status rejected")
	}
	for _, field := range []string{"ipRoutes", "exitNodes"} {
		text := strings.ReplaceAll(running, `"`+field+`":{}`, `"`+field+`":{"reconcileError":"failed"}`)
		if _, err := readyStatus(text); err == nil {
			t.Fatal("route reconciliation error ignored")
		}
	}
	if n, err := recvQueue("UNCONN 10 0 100.64.0.1:53 0.0.0.0:*\nUNCONN 7 0 [::]:53 [::]:*\nUNCONN 9 0 0.0.0.0:5353 0.0.0.0:*"); err != nil || n != 17 {
		t.Fatal("incorrect DNS queue barrier")
	}
	if _, err := recvQueue("UNCONN bad 0 0.0.0.0:53 0.0.0.0:*"); err == nil {
		t.Fatal("accepted invalid queue")
	}
}

func TestCLI(t *testing.T) {
	for _, args := range [][]string{{"--timeout=NaN"}, {"--timeout=Inf"}, {"--timeout=-1"}, {"--timeout=0"}, {"--timeout=1e100"}, {"extra"}, {"--remove-private", "--cleanup"}} {
		if _, _, err := parseOptions(args); err == nil {
			t.Fatal("accepted invalid options")
		}
	}
	if opts, _, err := parseOptions(nil); err != nil || opts.timeout != 720*time.Second {
		t.Fatal("default options")
	}
	var stdout, stderr bytes.Buffer
	if runMain([]string{"--help"}, &stdout, &stderr) != 0 || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatal("missing help")
	}
	t.Setenv("TAILMIX_E2E_RUN_ID", "")
	if runMain([]string{"--cleanup"}, &stdout, &stderr) == 0 {
		t.Fatal("cleanup accepted missing identity")
	}
}

func TestProcessFixture(t *testing.T) {
	if os.Getenv("TAILMIX_NETWORK_FIXTURE") != "sleep" {
		return
	}
	fmt.Fprint(os.Stdout, "private fixture output")
	fmt.Fprint(os.Stderr, "private fixture error")
	for {
		time.Sleep(time.Hour)
	}
}

func fixtureCommand(t *testing.T) command {
	t.Helper()
	t.Setenv("TAILMIX_NETWORK_FIXTURE", "sleep")
	return command{argv: []string{os.Args[0], "-test.run=^TestProcessFixture$"}, timeout: time.Hour}
}

func TestPollBoundsNestedCommand(t *testing.T) {
	spec := fixtureCommand(t)
	original := runner{context.Background()}
	r := rig{runner: original}
	started := time.Now()
	err := guarded(func() {
		r.poll(100*time.Millisecond, func() bool {
			_, err := r.run(spec)
			if err != nil {
				panic(err)
			}
			return true
		})
	})
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("nested command escaped readiness deadline")
	}
	if r.runner.ctx != original.ctx {
		t.Fatal("poll did not restore runner context")
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("subprocess diagnostics leaked")
	}
}

func TestPollRejectsLateSuccess(t *testing.T) {
	if err := poll(context.Background(), time.Millisecond, func() bool { time.Sleep(10 * time.Millisecond); return true }); err == nil {
		t.Fatal("accepted readiness after deadline")
	}
}

func TestPendingCancellation(t *testing.T) {
	spec := fixtureCommand(t)
	p, err := (runner{context.Background()}).launch(spec)
	if err != nil {
		t.Fatal(err)
	}
	p.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range 2 {
		if _, err := p.wait(ctx); err == nil {
			t.Fatal("canceled process returned success")
		}
	}
	if ctx.Err() != nil {
		t.Fatal("canceled subprocess was not reaped")
	}
}
