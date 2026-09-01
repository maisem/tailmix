package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/maisem/tailmix/state"
	tailmixupdate "github.com/maisem/tailmix/update"
)

type fakeBinaryUpdater struct {
	release    tailmixupdate.Release
	newer      bool
	applyError error
	rolledBack string
	applied    chan struct{}
}

func (u *fakeBinaryUpdater) Check(context.Context, string) (tailmixupdate.Release, bool, error) {
	return u.release, u.newer, nil
}

func (u *fakeBinaryUpdater) Apply(context.Context, string) (tailmixupdate.Release, string, bool, error) {
	if u.applied != nil {
		select {
		case u.applied <- struct{}{}:
		default:
		}
	}
	return u.release, "versions/v1.0.0", u.newer && u.applyError == nil, u.applyError
}

func (u *fakeBinaryUpdater) Rollback(target string) error {
	u.rolledBack = target
	return nil
}

func TestUpdateControlPersistsDefaultOnPolicyAndAppliesPair(t *testing.T) {
	store := state.NewJSONStore(filepath.Join(t.TempDir(), "state.json"))
	if err := store.Save(state.State{}); err != nil {
		t.Fatal(err)
	}
	updater := &fakeBinaryUpdater{release: tailmixupdate.Release{Version: "v1.1.0"}, newer: true}
	s := newSupervisor(store, state.State{}, nil, daemonConfig{
		Updater:    updater,
		Version:    "v1.0.0",
		UpdateRoot: t.TempDir(),
	})
	s.ctx = context.Background()

	status, err := s.UpdateStatus(context.Background())
	if err != nil || !status.Enabled || status.State != "idle" {
		t.Fatalf("initial status = %+v, %v", status, err)
	}
	status, err = s.CheckForUpdate(context.Background())
	if err != nil || status.State != "available" || status.AvailableVersion != "v1.1.0" {
		t.Fatalf("checked status = %+v, %v", status, err)
	}
	status, err = s.SetUpdatesEnabled(context.Background(), false)
	if err != nil || status.Enabled {
		t.Fatalf("disabled status = %+v, %v", status, err)
	}
	loaded, err := store.Load()
	if err != nil || !loaded.Updates.Disabled {
		t.Fatalf("persisted updates = %+v, %v", loaded.Updates, err)
	}
	status, err = s.ApplyUpdate(context.Background())
	if err != nil || status.State != "restarting" {
		t.Fatalf("apply status = %+v, %v", status, err)
	}
	select {
	case restart := <-s.updateRestart:
		if restart.oldTarget != "versions/v1.0.0" {
			t.Fatalf("rollback target = %q", restart.oldTarget)
		}
	case <-time.After(time.Second):
		t.Fatal("update did not request restart")
	}
}

func TestApplyUpdateRecordsFailureWithoutRestart(t *testing.T) {
	store := state.NewJSONStore(filepath.Join(t.TempDir(), "state.json"))
	if err := store.Save(state.State{}); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("download failed")
	s := newSupervisor(store, state.State{}, nil, daemonConfig{
		Updater: &fakeBinaryUpdater{applyError: wantErr}, Version: "v1.0.0",
	})
	s.ctx = context.Background()
	status, err := s.ApplyUpdate(context.Background())
	if !errors.Is(err, wantErr) || status.State != "error" || status.LastError != wantErr.Error() {
		t.Fatalf("ApplyUpdate = %+v, %v", status, err)
	}
	select {
	case <-s.updateRestart:
		t.Fatal("failed update requested restart")
	default:
	}
}

func TestInstalledUpdateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tailmix")
	if got := installedUpdateRoot(filepath.Join(root, "current", "tailmixd")); got != root {
		t.Fatalf("installedUpdateRoot = %q, want %q", got, root)
	}
	if got := installedUpdateRoot(filepath.Join(root, "tailmixd")); got != "" {
		t.Fatalf("non-versioned installedUpdateRoot = %q", got)
	}
}

func TestDefaultUpdateDelayRanges(t *testing.T) {
	for range 100 {
		if delay := defaultUpdateDelay(true); delay < 5*time.Minute || delay >= 30*time.Minute {
			t.Fatalf("initial delay = %v", delay)
		}
		if delay := defaultUpdateDelay(false); delay < 23*time.Hour || delay >= 25*time.Hour {
			t.Fatalf("daily delay = %v", delay)
		}
	}
}

func TestUpdateLoopAutomaticallyAppliesWhenEnabled(t *testing.T) {
	store := state.NewJSONStore(filepath.Join(t.TempDir(), "state.json"))
	if err := store.Save(state.State{}); err != nil {
		t.Fatal(err)
	}
	updater := &fakeBinaryUpdater{release: tailmixupdate.Release{Version: "v1.1.0"}, newer: true}
	s := newSupervisor(store, state.State{}, nil, daemonConfig{
		Updater: updater, Version: "v1.0.0", UpdateRoot: t.TempDir(),
		UpdateDelay: func(bool) time.Duration { return time.Millisecond },
	})
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runUpdateLoop(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case restart := <-s.updateRestart:
		if restart.oldTarget != "versions/v1.0.0" {
			t.Fatalf("rollback target = %q", restart.oldTarget)
		}
	case <-time.After(time.Second):
		t.Fatal("automatic update did not request restart")
	}
}

func TestUpdateLoopWaitsWhileDisabled(t *testing.T) {
	store := state.NewJSONStore(filepath.Join(t.TempDir(), "state.json"))
	st := state.State{Updates: state.UpdateState{Disabled: true}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	applied := make(chan struct{}, 1)
	updater := &fakeBinaryUpdater{
		release: tailmixupdate.Release{Version: "v1.1.0"}, newer: true, applied: applied,
	}
	s := newSupervisor(store, st, nil, daemonConfig{
		Updater: updater, Version: "v1.0.0", UpdateRoot: t.TempDir(),
		UpdateDelay: func(bool) time.Duration { return time.Millisecond },
	})
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runUpdateLoop(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case <-applied:
		t.Fatal("disabled updater applied an update")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := s.SetUpdatesEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("enabled updater did not resume")
	}
}

func TestUpdateRestartRollsBackBeforeRetry(t *testing.T) {
	updater := &fakeBinaryUpdater{}
	restart := &updateRestart{root: t.TempDir(), oldTarget: "versions/v1.0.0", updater: updater}
	wantFirst := errors.New("new binary failed")
	wantSecond := errors.New("old binary failed")
	calls := 0
	oldExec := execProcess
	execProcess = func(string, []string, []string) error {
		calls++
		if calls == 1 {
			return wantFirst
		}
		return wantSecond
	}
	t.Cleanup(func() { execProcess = oldExec })
	err := restart.exec([]string{"tailmixd", "-state=test"}, []string{"A=B"})
	if !errors.Is(err, wantFirst) || updater.rolledBack != restart.oldTarget || calls != 2 {
		t.Fatalf("exec error = %v, rollback = %q, calls = %d", err, updater.rolledBack, calls)
	}
}
