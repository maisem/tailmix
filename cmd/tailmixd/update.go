package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"syscall"
	"time"

	"github.com/maisem/tailmix/controlapi"
	tailmixupdate "github.com/maisem/tailmix/update"
)

type binaryUpdater interface {
	Check(context.Context, string) (tailmixupdate.Release, bool, error)
	Apply(context.Context, string) (tailmixupdate.Release, string, bool, error)
	Rollback(string) error
}

type updateRestart struct {
	root      string
	oldTarget string
	updater   binaryUpdater
}

func (r *updateRestart) Error() string { return "restart into installed update" }

var execProcess = syscall.Exec

func (r *updateRestart) exec(argv, env []string) error {
	path := filepath.Join(r.root, "current", "tailmixd")
	args := append([]string{path}, argv[1:]...)
	if err := execProcess(path, args, env); err == nil {
		return nil
	} else if rollbackErr := r.updater.Rollback(r.oldTarget); rollbackErr != nil {
		return fmt.Errorf("start updated daemon: %w; rollback: %v", err, rollbackErr)
	} else if retryErr := execProcess(path, args, env); retryErr != nil {
		return fmt.Errorf("start updated daemon: %w; start rolled-back daemon: %v", err, retryErr)
	}
	return nil
}

func defaultUpdateDelay(initial bool) time.Duration {
	if initial {
		return 5*time.Minute + time.Duration(rand.Int64N(int64(25*time.Minute)))
	}
	return 23*time.Hour + time.Duration(rand.Int64N(int64(2*time.Hour)))
}

func (s *supervisor) runUpdateLoop(ctx context.Context) {
	initial := true
	for {
		if !s.updatesEnabled() {
			select {
			case <-ctx.Done():
				return
			case <-s.updateWake:
				continue
			}
		}
		delay := s.cfg.UpdateDelay
		if delay == nil {
			delay = defaultUpdateDelay
		}
		timer := time.NewTimer(delay(initial))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.updateWake:
			if !timer.Stop() {
				<-timer.C
			}
			continue
		case <-timer.C:
		}
		initial = false
		status, err := s.applyUpdate(ctx)
		if err != nil {
			fmt.Fprintf(s.cfg.Stderr, "automatic update failed: %v\n", err)
			continue
		}
		if status.State == "restarting" {
			return
		}
	}
}

func (s *supervisor) updatesEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Updater != nil && !s.st.Updates.Disabled
}

func (s *supervisor) UpdateStatus(context.Context) (controlapi.UpdateStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateStatusLocked(), nil
}

func (s *supervisor) SetUpdatesEnabled(_ context.Context, enabled bool) (controlapi.UpdateStatus, error) {
	if s.cfg.Updater == nil {
		return controlapi.UpdateStatus{}, controlapi.NewError("unsupported", "this installation does not support automatic updates")
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.mu.Lock()
	s.st.Updates.Disabled = !enabled
	if s.st.Updates.State == "" {
		s.st.Updates.State = "idle"
	}
	err := s.store.Save(s.st)
	status := s.updateStatusLocked()
	s.mu.Unlock()
	if err != nil {
		return controlapi.UpdateStatus{}, fmt.Errorf("save update policy: %w", err)
	}
	select {
	case s.updateWake <- struct{}{}:
	default:
	}
	return status, nil
}

func (s *supervisor) CheckForUpdate(ctx context.Context) (controlapi.UpdateStatus, error) {
	if s.cfg.Updater == nil {
		return controlapi.UpdateStatus{}, controlapi.NewError("unsupported", "this installation does not support automatic updates")
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if status, restarting := s.restartingUpdateStatus(); restarting {
		return status, nil
	}
	if err := s.setUpdateActivity("checking", "", "", false); err != nil {
		return controlapi.UpdateStatus{}, err
	}
	release, newer, err := s.cfg.Updater.Check(ctx, s.cfg.Version)
	available := ""
	stateName := "idle"
	lastError := ""
	if newer {
		available = release.Version
		stateName = "available"
	}
	if err != nil {
		stateName, lastError = "error", err.Error()
	}
	if saveErr := s.setUpdateActivity(stateName, available, lastError, true); saveErr != nil {
		return controlapi.UpdateStatus{}, errors.Join(err, saveErr)
	}
	status, _ := s.UpdateStatus(ctx)
	return status, err
}

func (s *supervisor) ApplyUpdate(ctx context.Context) (controlapi.UpdateStatus, error) {
	return s.applyUpdate(ctx)
}

func (s *supervisor) applyUpdate(ctx context.Context) (controlapi.UpdateStatus, error) {
	if s.cfg.Updater == nil {
		return controlapi.UpdateStatus{}, controlapi.NewError("unsupported", "this installation does not support automatic updates")
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if status, restarting := s.restartingUpdateStatus(); restarting {
		return status, nil
	}
	if err := s.setUpdateActivity("applying", "", "", false); err != nil {
		return controlapi.UpdateStatus{}, err
	}
	release, oldTarget, updated, err := s.cfg.Updater.Apply(ctx, s.cfg.Version)
	stateName, available, lastError := "idle", "", ""
	if err != nil {
		stateName, lastError = "error", err.Error()
	} else if updated {
		stateName, available = "restarting", release.Version
	}
	if saveErr := s.setUpdateActivity(stateName, available, lastError, true); saveErr != nil {
		if updated {
			_ = s.cfg.Updater.Rollback(oldTarget)
		}
		return controlapi.UpdateStatus{}, errors.Join(err, saveErr)
	}
	status, _ := s.UpdateStatus(ctx)
	if err != nil {
		return status, err
	}
	if updated {
		restart := updateRestart{root: s.cfg.UpdateRoot, oldTarget: oldTarget, updater: s.cfg.Updater}
		time.AfterFunc(250*time.Millisecond, func() {
			select {
			case s.updateRestart <- restart:
			case <-s.ctx.Done():
			}
		})
	}
	return status, nil
}

func (s *supervisor) restartingUpdateStatus() (controlapi.UpdateStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateStatusLocked(), s.st.Updates.State == "restarting"
}

func (s *supervisor) setUpdateActivity(activity, available, lastError string, checked bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Updates.State = activity
	s.st.Updates.AvailableVersion = available
	s.st.Updates.LastError = lastError
	if checked {
		s.st.Updates.LastChecked = time.Now().UTC().Format(time.RFC3339)
	}
	if err := s.store.Save(s.st); err != nil {
		return fmt.Errorf("save update status: %w", err)
	}
	return nil
}

func (s *supervisor) updateStatusLocked() controlapi.UpdateStatus {
	stateName := s.st.Updates.State
	if stateName == "" {
		stateName = "idle"
	}
	if s.cfg.Updater == nil {
		stateName = "unsupported"
	}
	return controlapi.UpdateStatus{
		Enabled:          s.cfg.Updater != nil && !s.st.Updates.Disabled,
		CurrentVersion:   s.cfg.Version,
		AvailableVersion: s.st.Updates.AvailableVersion,
		State:            stateName,
		LastChecked:      s.st.Updates.LastChecked,
		LastError:        s.st.Updates.LastError,
	}
}

var _ controlapi.UpdateBackend = (*supervisor)(nil)
