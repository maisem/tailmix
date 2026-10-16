//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type mount struct {
	Type        string
	Source      string
	Destination string
}

// resolvePath follows existing symlinks even when the final path (or a symlink
// target) does not exist yet. This prevents a shared-bind escape through a
// dangling symlink as well as through an ordinary existing symlink.
func resolvePath(path string) (string, error) {
	// Abs and Join clean ".." before resolving symlinks, which can turn an
	// unshared target into an apparently shared path.
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", failure("path resolution")
		}
		path = cwd + string(filepath.Separator) + path
	}
	todo := strings.Split(path, string(filepath.Separator))
	resolved := string(filepath.Separator)
	links := 0
	for len(todo) != 0 {
		part := todo[0]
		todo = todo[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		info, err := os.Lstat(next)
		if err != nil && !os.IsNotExist(err) {
			return "", failure("path resolution")
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 255 {
				return "", failure("path resolution")
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", failure("path resolution")
			}
			if filepath.IsAbs(target) {
				resolved = string(filepath.Separator)
			}
			todo = append(strings.Split(target, string(filepath.Separator)), todo...)
		} else {
			resolved = next
		}
	}
	return resolved, nil
}

func daemonPath(path string, mounts []mount) (string, error) {
	local, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	if mounts == nil {
		return local, nil
	}
	best := -1
	relative := ""
	for i, m := range mounts {
		if !filepath.IsAbs(m.Destination) {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(m.Destination), local)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if best == -1 || len(filepath.Clean(m.Destination)) > len(filepath.Clean(mounts[best].Destination)) {
			best, relative = i, rel
		}
	}
	if best == -1 {
		return "", failure("path is not shared with Docker daemon")
	}
	m := mounts[best]
	if m.Type != "bind" || !filepath.IsAbs(m.Source) {
		return "", failure("path is hidden by a non-bind mount")
	}
	return filepath.Join(m.Source, relative), nil
}

var safeIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ownContainerMounts(inspect func(string) result, environHostname, hostname string) ([]mount, error) {
	hostname = strings.TrimSpace(hostname)
	seen := map[string]bool{}
	for _, candidate := range []string{environHostname, hostname} {
		if !safeIdentity.MatchString(candidate) || seen[candidate] {
			continue
		}
		seen[candidate] = true
		res := inspect(candidate)
		if res.code != 0 {
			continue
		}
		var infos []struct {
			ID     string `json:"Id"`
			Config struct{ Hostname string }
			Mounts []mount
		}
		if json.Unmarshal([]byte(res.stdout), &infos) != nil || len(infos) != 1 {
			continue
		}
		info := infos[0]
		if len(info.ID) < 12 {
			continue
		}
		identities := map[string]bool{info.ID: true, info.ID[:12]: true, info.Config.Hostname: true}
		if identities[hostname] && identities[candidate] && info.Mounts != nil {
			return info.Mounts, nil
		}
	}
	return nil, failure("cannot identify caller container bind mounts")
}

func findRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", failure("checkout root unavailable")
	}
	for {
		mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.HasPrefix(string(mod), "module github.com/maisem/tailmix\n") {
			if info, err := os.Stat(filepath.Join(dir, "integration", "linux_network.Dockerfile")); err == nil && info.Mode().IsRegular() {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", failure("checkout root unavailable")
		}
		dir = parent
	}
}

func privateWrite(path, text string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return failure("private file write")
	}
	defer f.Close()
	if f.Chmod(0o600) != nil {
		return failure("private file permissions")
	}
	if _, err := f.WriteString(text); err != nil {
		return failure("private file write")
	}
	if f.Close() != nil {
		return failure("private file write")
	}
	return nil
}
