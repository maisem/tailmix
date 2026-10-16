//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// failure contains only a fixed category, never subprocess output, argv, or
// operating-system errors (all of which can contain credentials or identities).
type failure string

func (f failure) Error() string { return string(f) }

type result struct {
	code   int
	stdout string
}

type command struct {
	argv    []string
	dir     string
	env     []string
	timeout time.Duration
	uncheck bool
}

type runner struct {
	ctx context.Context
}

// CommandContext alone kills only the immediate process. Kill the process group
// too, and bound pipe draining when a subprocess leaves inherited pipes open.
func prepareCommand(ctx context.Context, spec command) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.CommandContext(ctx, spec.argv[0], spec.argv[1:]...)
	cmd.Dir, cmd.Env = spec.dir, spec.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 250 * time.Millisecond
	out := new(bytes.Buffer)
	cmd.Stdout = out
	// Discard stderr rather than returning any daemon diagnostics.
	cmd.Stderr = nil
	return cmd, out
}

func commandError(ctx context.Context, err error, unchecked bool) error {
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return failure("interrupted")
		}
		return failure("command deadline")
	}
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if unchecked && errors.As(err, &exit) {
		return nil
	}
	return failure("command failed")
}

func (r runner) run(spec command) (result, error) {
	if r.ctx.Err() != nil {
		return result{}, failure("global deadline")
	}
	ctx, cancel := context.WithTimeout(r.ctx, spec.timeout)
	defer cancel()
	cmd, out := prepareCommand(ctx, spec)
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return result{code, out.String()}, commandError(ctx, err, spec.uncheck)
}

type pending struct {
	started time.Time
	cancel  context.CancelFunc
	done    chan pendingResult
}

type pendingResult struct {
	result result
	err    error
}

func (r runner) launch(spec command) (*pending, error) {
	if r.ctx.Err() != nil {
		return nil, failure("global deadline")
	}
	ctx, cancel := context.WithTimeout(r.ctx, spec.timeout)
	cmd, out := prepareCommand(ctx, spec)
	p := &pending{started: time.Now(), cancel: cancel, done: make(chan pendingResult, 1)}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, failure("command failed")
	}
	go func() {
		err := cmd.Wait()
		p.done <- pendingResult{
			result{cmd.ProcessState.ExitCode(), out.String()},
			commandError(ctx, err, spec.uncheck),
		}
		cancel()
	}()
	return p, nil
}

func (p *pending) wait(ctx context.Context) (result, error) {
	select {
	case done := <-p.done:
		// Preserve the result for idempotent cleanup after an assertion fails.
		p.done <- done
		return done.result, done.err
	case <-ctx.Done():
		p.cancel()
		return result{}, failure("command deadline")
	}
}

func poll(ctx context.Context, timeout time.Duration, predicate func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for ctx.Err() == nil {
		if predicate() && ctx.Err() == nil {
			return nil
		}
		timer := time.NewTimer(80 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return failure("readiness deadline")
}

// The orchestration is imperative; its internal assertions unwind to a single
// sanitized stage boundary. Cleanup guards each operation separately so one
// failure cannot skip later removals.
func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func require(ok bool, category string) {
	if !ok {
		panic(failure(category))
	}
}

func guarded(fn func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			if f, ok := p.(failure); ok {
				err = f
			} else {
				err = failure("internal failure")
			}
		}
	}()
	fn()
	return nil
}
