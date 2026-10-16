//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a real child/grandchild fixture; no external
// interpreter or shell is needed to exercise process groups and signals.
func TestBoundedHelper(t *testing.T) {
	mode := os.Getenv("TAILMIX_BOUNDED_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "success":
		os.Exit(0)
	case "artifact":
		if err := os.WriteFile("core", []byte("test artifact"), 0600); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "failure":
		os.Exit(7)
	case "descendant":
		signal.Ignore(syscall.SIGQUIT)
		if err := os.WriteFile(os.Getenv("TAILMIX_BOUNDED_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(2)
		}
		for {
			time.Sleep(time.Hour)
		}
	case "leader", "ignore":
		signals := make(chan os.Signal, 1)
		if mode == "ignore" {
			signal.Ignore(syscall.SIGQUIT)
		} else {
			signal.Notify(signals, syscall.SIGQUIT)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestBoundedHelper$")
		child.Env = append(os.Environ(), "TAILMIX_BOUNDED_HELPER=descendant")
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		if mode == "leader" {
			<-signals
			// Exit successfully on SIGQUIT while a descendant ignores it.
			os.Exit(0)
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(4)
	}
}

func helperCommand(t *testing.T, mode string) []string {
	t.Helper()
	// An immediate timeout can deliver SIGQUIT before the child installs its
	// runtime handlers. Keep any resulting core dump in test-owned storage.
	t.Chdir(t.TempDir())
	t.Setenv("TAILMIX_BOUNDED_HELPER", mode)
	// Race-instrumented child processes otherwise pause for one second during
	// os.Exit, obscuring the leader-exited-before-grace regression.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	return []string{os.Args[0], "-test.run=^TestBoundedHelper$"}
}

func TestHelperArtifactsAreRemoved(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot identify original working directory")
	}
	var workdir string
	// Register first so this runs after the helper's temporary-directory cleanup.
	t.Cleanup(func() {
		if workdir != "" {
			if _, err := os.Stat(workdir); !os.IsNotExist(err) {
				t.Error("helper artifact directory survived cleanup")
			}
		}
	})
	command := helperCommand(t, "artifact")
	cwd, err := os.Getwd()
	if err != nil || cwd == original {
		t.Fatal("helper still uses the package working directory")
	}
	workdir = cwd
	status, timedOut := runBounded(5*time.Second, time.Millisecond, command)
	if status != 0 || timedOut {
		t.Fatal("artifact helper did not exit successfully")
	}
	data, err := os.ReadFile(filepath.Join(workdir, "core"))
	if err != nil || string(data) != "test artifact" {
		t.Fatal("child artifact was not confined to test-owned storage")
	}
}

func TestRunBoundedExitStatus(t *testing.T) {
	for _, test := range []struct {
		mode string
		want int
	}{{"success", 0}, {"failure", 7}} {
		t.Run(test.mode, func(t *testing.T) {
			status, timedOut := runBounded(5*time.Second, time.Millisecond, helperCommand(t, test.mode))
			if status != test.want || timedOut {
				t.Fatalf("got (%d, %v), want (%d, false)", status, timedOut, test.want)
			}
		})
	}
}

func TestRunBoundedKillsProcessGroup(t *testing.T) {
	for _, mode := range []string{"leader", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			pidPath := filepath.Join(t.TempDir(), "pid")
			t.Setenv("TAILMIX_BOUNDED_PID", pidPath)
			start := time.Now()
			// Allow cold, race-instrumented child and grandchild startup on
			// constrained CI runners before exercising the actual deadline.
			status, timedOut := runBounded(2*time.Second, 20*time.Millisecond, helperCommand(t, mode))
			if status != 124 || !timedOut {
				t.Fatalf("got (%d, %v), want timeout", status, timedOut)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatal("timeout did not bound process lifetime")
			}
			data, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatal("descendant never became ready:", err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			deadline := time.Now().Add(time.Second)
			for {
				state, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				// A zombie is dead and awaiting its reparented reaper, not a
				// surviving benchmark descendant.
				if os.IsNotExist(err) || (err == nil && strings.Contains(string(state), ") Z ")) {
					break
				}
				if !time.Now().Before(deadline) {
					t.Fatal("descendant survived process-group termination")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestDeadlineAlwaysReturnsTimeout(t *testing.T) {
	command := helperCommand(t, "success")
	for range 10 {
		status, timedOut := runBounded(0, time.Millisecond, command)
		if status != 124 || !timedOut {
			t.Fatalf("exit at deadline returned (%d, %v)", status, timedOut)
		}
	}
}

func TestRunArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"1"}, {"nan", "x"}, {"inf", "x"}, {"-1", "x"}, {"1e100", "x"}, {"1", "--"}, {"1", "/nonexistent/tailmix-benchmark"}} {
		var stderr bytes.Buffer
		if got := run(args, &stderr); got != 1 || stderr.Len() == 0 {
			t.Fatalf("run(%q) = %d, stderr=%q", args, got, stderr.String())
		}
	}
	command := helperCommand(t, "success")
	var stderr bytes.Buffer
	if got := run(append([]string{"0", "--"}, command...), &stderr); got != 124 || stderr.String() != "benchmark timed out after 0s\n" {
		t.Fatalf("got status=%d stderr=%q", got, stderr.String())
	}
}
