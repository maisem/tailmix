//go:build linux

// Command run-bounded-benchmark runs a command in an isolated process group.
package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "usage: run-bounded-benchmark SECONDS COMMAND [ARG ...]")
		return 1
	}
	seconds, err := strconv.ParseFloat(args[0], 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds >= float64(math.MaxInt64)/float64(time.Second) {
		fmt.Fprintln(stderr, "invalid timeout")
		return 1
	}
	command := args[1:]
	if command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		fmt.Fprintln(stderr, "missing command")
		return 1
	}
	status, timedOut := runBounded(time.Duration(seconds*float64(time.Second)), 5*time.Second, command)
	if timedOut {
		fmt.Fprintf(stderr, "benchmark timed out after %gs\n", seconds)
	} else if status == -1 {
		fmt.Fprintln(stderr, "could not start benchmark")
		return 1
	}
	return status
}

func runBounded(timeout, grace time.Duration, command []string) (status int, timedOut bool) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return -1, false
	}
	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	reaped := false
	select {
	case waitErr = <-done:
		reaped = true
		// A successful exit observed after the deadline is still a timeout.
		if time.Now().Before(deadline) {
			return exitStatus(waitErr), false
		}
	case <-timer.C:
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGQUIT)
	if !reaped {
		graceTimer := time.NewTimer(grace)
		select {
		case <-done:
			reaped = true
		case <-graceTimer.C:
		}
		graceTimer.Stop()
	}
	// Always kill the group, even if its leader exited during SIGQUIT. A
	// surviving descendant must not escape the benchmark's time bound.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if !reaped {
		<-done
	}
	return 124, true
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exit.ExitCode()
	}
	return 1
}
