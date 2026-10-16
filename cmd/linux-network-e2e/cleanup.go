//go:build linux

package main

import (
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const runLabel = "io.github.maisem.tailmix.e2e-run"

var safeRunID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var privateID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func lifecycleLabels(runID string, required bool) ([]string, error) {
	if runID == "" && !required {
		return nil, nil
	}
	if !safeRunID.MatchString(runID) {
		return nil, failure("invalid or missing cleanup run ID")
	}
	return []string{"--label", runLabel + "=" + runID}, nil
}

type dockerFunc func(bool, time.Duration, ...string) result

func cleanupRun(runID string, docker dockerFunc) {
	_ = must(lifecycleLabels(runID, true))
	selected := "label=" + runLabel + "=" + runID
	prefix := `tailmix-e2e-[0-9a-f]{32}-`
	groups := []struct {
		list     []string
		template string
		pattern  string
		remove   []string
	}{
		{[]string{"ps", "-a"}, "{{.Names}}", prefix + `(control|peer|client|cleanup)`, []string{"rm", "-f"}},
		{[]string{"network", "ls"}, "{{.Name}}", prefix + `net`, []string{"network", "rm"}},
		{[]string{"image", "ls"}, "{{.Repository}}:{{.Tag}}", prefix + `tools:latest`, []string{"image", "rm"}},
	}
	for _, group := range groups {
		args := append(append([]string(nil), group.list...), "--filter", selected, "--format", group.template)
		res := docker(true, 15*time.Second, args...)
		match := regexp.MustCompile("^" + group.pattern + "$")
		names := strings.Split(res.stdout, "\n")
		sort.Strings(names)
		previous := ""
		for _, name := range names {
			if name != previous && match.MatchString(name) {
				docker(true, 15*time.Second, append(append([]string(nil), group.remove...), name)...)
			}
			previous = name
		}
	}
	docker(true, 10*time.Second, "info")
}

func copyCleanupHelper(destination string) error {
	source, err := os.Executable()
	if err != nil {
		return failure("cleanup helper unavailable")
	}
	// It must run in the Alpine tools image without a host dynamic loader.
	binary, err := elf.Open(source)
	if err != nil {
		return failure("static cleanup helper required")
	}
	defer binary.Close()
	for _, prog := range binary.Progs {
		if prog.Type == elf.PT_INTERP {
			return failure("static cleanup helper required")
		}
	}
	in, err := os.Open(source)
	if err != nil {
		return failure("cleanup helper unavailable")
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return failure("cleanup helper copy")
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return failure("cleanup helper copy")
	}
	if out.Close() != nil {
		return failure("cleanup helper copy")
	}
	return nil
}

func exactCleanupMount(mountinfo string) bool {
	for _, line := range strings.Split(mountinfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[4] == "/cleanup" {
			return true
		}
	}
	return false
}

// No path argument is accepted. This internal mode cannot remove the caller's
// directory: it requires an exact mount at /cleanup, an owner marker, and no
// symlink at the mount root. RemoveAll never follows a symlink entry.
func removePrivateFiles() error {
	if os.Geteuid() != 0 {
		return failure("private cleanup requires isolated mount")
	}
	info, err := os.Lstat("/cleanup")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return failure("private cleanup requires isolated mount")
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || !exactCleanupMount(string(mountinfo)) {
		return failure("private cleanup requires isolated mount")
	}
	marker, err := os.ReadFile("/cleanup/.tailmix-e2e-owner")
	if err != nil || !privateID.Match(marker) {
		return failure("private cleanup requires owner marker")
	}
	entries, err := os.ReadDir("/cleanup")
	if err != nil {
		return failure("private cleanup read")
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join("/cleanup", entry.Name())); err != nil {
			return failure("private cleanup remove")
		}
	}
	return nil
}

func (r *rig) cleanup() {
	incomplete := false
	attempt := func(fn func()) {
		if guarded(fn) != nil {
			incomplete = true
		}
	}
	if r.paused {
		attempt(func() { r.pause("CONT") })
	}
	if r.clientStarted {
		attempt(func() {
			r.ex(false, 15*time.Second, "client", "sh", "-c", "kill -TERM $(cat /private/app.pid)")
		})
		attempt(func() {
			r.poll(8*time.Second, func() bool {
				return r.ex(false, 2*time.Second, "client", "sh", "-c",
					"kill -0 $(cat /private/app.pid) 2>/dev/null").code != 0
			})
		})
	}
	// Inspect every UUID name even if cancellation interrupted Docker create
	// after the daemon succeeded but before the CLI reported success.
	for i := len(roles) - 1; i >= 0; i-- {
		name := r.names[roles[i]]
		attempt(func() {
			if r.docker(false, 5*time.Second, "container", "inspect", name).code == 0 {
				r.d("rm", "-f", name)
			}
		})
	}
	for _, p := range r.pending {
		p.cancel()
		// A canceled accepted query is expected during failure cleanup.
		attempt(func() {
			_, err := p.wait(r.ctx)
			require(err == nil || r.ctx.Err() == nil, "query cleanup deadline")
		})
	}
	attempt(func() {
		if r.docker(false, 5*time.Second, "network", "inspect", r.network).code == 0 {
			r.d("network", "rm", r.network)
		}
	})
	for _, role := range roles {
		attempt(func() {
			require(r.docker(false, 5*time.Second, "container", "inspect", r.names[role]).code != 0,
				"test container leaked")
		})
	}
	attempt(func() {
		require(r.docker(false, 5*time.Second, "network", "inspect", r.network).code != 0, "test network leaked")
	})
	if _, err := os.Stat(r.tmp); err == nil {
		attempt(func() {
			if r.docker(false, 5*time.Second, "image", "inspect", r.image).code == 0 {
				r.removePrivate()
			}
		})
		attempt(func() { require(os.RemoveAll(r.tmp) == nil, "private directory removal") })
	}
	attempt(func() {
		if r.docker(false, 5*time.Second, "image", "inspect", r.image).code == 0 {
			r.d("image", "rm", r.image)
		}
	})
	// An unavailable daemon cannot prove the absence of test resources.
	attempt(func() { r.docker(true, 10*time.Second, "info") })
	require(!incomplete, "cleanup incomplete")
}

func (r *rig) removePrivate() {
	name := r.prefix + "-cleanup"
	defer func() {
		r.docker(false, 5*time.Second, "rm", "-f", name)
	}()
	args := append([]string{"run", "--rm"}, r.labels...)
	args = append(args, "--name", name, "--network=none", "--log-driver=none",
		"--mount", "type=bind,src="+r.bind(r.tmp)+",dst=/cleanup",
		"--entrypoint=/cleanup/cleanup-helper", r.image, "--remove-private")
	r.d(args...)
	require(r.docker(false, 5*time.Second, "container", "inspect", name).code != 0, "private cleanup container leaked")
}
