package mkversion

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDerive(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		changeCount int
		hash        string
		released    bool
		wantShort   string
		wantLong    string
		wantErr     bool
	}{
		{
			name:      "development target",
			version:   "0.1.0-dev",
			hash:      "0123456789abcdef",
			wantShort: "v0.1.0-dev",
			wantLong:  "v0.1.0-dev-t012345678",
		},
		{
			name:        "development commits",
			version:     "0.2.0-dev",
			changeCount: 12,
			hash:        "0123456789abcdef",
			wantShort:   "v0.2.0-dev.12",
			wantLong:    "v0.2.0-dev.12-t012345678",
		},
		{
			name:        "release candidate commits",
			version:     "0.1.1-rc",
			changeCount: 4,
			hash:        "0123456789abcdef",
			wantShort:   "v0.1.1-rc.4",
			wantLong:    "v0.1.1-rc.4-t012345678",
		},
		{
			name:        "tagged release",
			version:     "0.1.0-dev",
			changeCount: 12,
			hash:        "0123456789abcdef",
			released:    true,
			wantShort:   "v0.1.0",
			wantLong:    "v0.1.0-t012345678",
		},
		{
			name:        "negative change count",
			version:     "0.1.0-dev",
			changeCount: -1,
			wantErr:     true,
		},
		{
			name:    "missing channel",
			version: "0.1.0",
			wantErr: true,
		},
		{
			name:    "invalid semantic version",
			version: "0.1-dev",
			wantErr: true,
		},
		{
			name:    "build metadata",
			version: "0.1.0-dev+local",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := parseVersion(test.version)
			if err == nil {
				var info Info
				info, err = derive(target, test.changeCount, test.hash, test.released)
				if err == nil && (info.Short != test.wantShort || info.Long != test.wantLong) {
					t.Fatalf("derive() = %+v, want short=%q long=%q", info, test.wantShort, test.wantLong)
				}
			}
			if test.wantErr {
				if err == nil {
					t.Fatal("derive() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInfoFromUsesMatchingCleanReleaseTag(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "version"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, versionFile), []byte("0.1.0-dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init")
	runGit(t, root, "add", versionFile)
	runGit(t, root, "-c", "user.name=Tailmix Test", "-c", "user.email=tailmix@example.invalid", "commit", "-m", "version target")

	info, err := InfoFrom(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Short, "v0.1.0-dev"; got != want {
		t.Fatalf("untagged version = %q, want %q", got, want)
	}

	runGit(t, root, "tag", "v9.9.9")
	info, err = InfoFrom(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Short, "v0.1.0-dev"; got != want {
		t.Fatalf("mismatched-tag version = %q, want %q", got, want)
	}

	runGit(t, root, "tag", "v0.1.0")
	info, err = InfoFrom(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Short, "v0.1.0"; got != want {
		t.Fatalf("release version = %q, want %q", got, want)
	}

	if err := os.WriteFile(filepath.Join(root, "untracked.go"), []byte("package untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err = InfoFrom(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Short, "v0.1.0-dev"; got != want {
		t.Fatalf("dirty tagged version = %q, want %q", got, want)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
