// Package mkversion derives Tailmix build versions from Git history.
package mkversion

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

const versionFile = "version/VERSION.txt"

// Info is the version information derived for a Tailmix build.
type Info struct {
	Short       string
	Long        string
	GitHash     string
	ChangeCount int
}

// InfoFrom derives version information from the Git repository containing dir.
func InfoFrom(dir string) (Info, error) {
	root, err := gitOutput(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return Info{}, fmt.Errorf("finding Git root: %w", err)
	}
	hash, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return Info{}, fmt.Errorf("getting Git hash: %w", err)
	}
	baseHash, err := gitOutput(root, "rev-list", "--max-count=1", hash, "--", versionFile)
	if err != nil {
		return Info{}, fmt.Errorf("finding last %s change: %w", versionFile, err)
	}
	if baseHash == "" {
		return Info{}, fmt.Errorf("%s is not committed", filepath.Join(root, versionFile))
	}
	version, err := gitOutput(root, "show", baseHash+":"+versionFile)
	if err != nil {
		return Info{}, fmt.Errorf("reading %s at %s: %w", versionFile, baseHash, err)
	}
	target, err := parseVersion(version)
	if err != nil {
		return Info{}, err
	}
	rawCount, err := gitOutput(root, "rev-list", "--count", hash, "^"+baseHash)
	if err != nil {
		return Info{}, fmt.Errorf("counting changes since %s: %w", baseHash, err)
	}
	changeCount, err := strconv.Atoi(rawCount)
	if err != nil {
		return Info{}, fmt.Errorf("parsing change count %q: %w", rawCount, err)
	}
	releaseTags, err := gitOutput(root, "tag", "--points-at", hash, "--list", target.releaseTag())
	if err != nil {
		return Info{}, fmt.Errorf("finding release tag: %w", err)
	}
	released := releaseTags == target.releaseTag()
	if released {
		status, err := gitOutput(root, "status", "--porcelain", "--untracked-files=normal")
		if err != nil {
			return Info{}, fmt.Errorf("checking worktree status: %w", err)
		}
		released = status == ""
	}
	return derive(target, changeCount, hash, released)
}

func derive(target targetVersion, changeCount int, hash string, released bool) (Info, error) {
	if changeCount < 0 {
		return Info{}, fmt.Errorf("change count must not be negative")
	}

	short := target.version
	if released {
		short = target.core
	} else if changeCount != 0 {
		short += "." + strconv.Itoa(changeCount)
	}
	long := short
	if hash != "" {
		long += "-t" + shortHash(hash)
	}
	return Info{
		Short:       short,
		Long:        long,
		GitHash:     hash,
		ChangeCount: changeCount,
	}, nil
}

type targetVersion struct {
	version string
	core    string
}

func parseVersion(raw string) (targetVersion, error) {
	version := "v" + strings.TrimSpace(raw)
	if !semver.IsValid(version) {
		return targetVersion{}, fmt.Errorf("parsing version %q: want valid semantic version without leading v", raw)
	}
	if semver.Build(version) != "" {
		return targetVersion{}, fmt.Errorf("parsing version %q: build metadata is not supported", raw)
	}
	prerelease := semver.Prerelease(version)
	if prerelease == "" {
		return targetVersion{}, fmt.Errorf("parsing version %q: prerelease channel is required", raw)
	}
	return targetVersion{
		version: version,
		core:    strings.TrimSuffix(version, prerelease),
	}, nil
}

func (target targetVersion) releaseTag() string {
	return target.core
}

func shortHash(hash string) string {
	if len(hash) > 9 {
		return hash[:9]
	}
	return hash
}

func gitOutput(dir string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
