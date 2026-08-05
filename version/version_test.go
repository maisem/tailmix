package version

import (
	"runtime/debug"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

func TestEmbeddedVersionIsSemver(t *testing.T) {
	version := "v" + strings.TrimSpace(versionDotTxt)
	if !semver.IsValid(version) {
		t.Fatalf("embedded version %q is not valid semver", version)
	}
}

func TestTailscaleVersionFromBuildInfo(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{{
		Path:    "tailscale.com",
		Version: "v1.101.0-pre.0.20260630140925-fad8b9b8a957",
	}}}
	if got, want := tailscaleVersionFromBuildInfo(info), "v1.101.0-pre.0.20260630140925-fad8b9b8a957"; got != want {
		t.Fatalf("tailscaleVersionFromBuildInfo() = %q, want %q", got, want)
	}
}

func TestTailscaleVersionFromReplacement(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{{
		Path:    "tailscale.com",
		Version: "v1.100.0",
		Replace: &debug.Module{
			Path:    "example.com/tailscale",
			Version: "v1.101.2-fork.1",
		},
	}}}
	if got, want := tailscaleVersionFromBuildInfo(info), "v1.101.2-fork.1"; got != want {
		t.Fatalf("tailscaleVersionFromBuildInfo() = %q, want %q", got, want)
	}
}

func TestMetaFromBuildInfo(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef"},
		{Key: "vcs.time", Value: "2026-07-27T12:34:56Z"},
		{Key: "vcs.modified", Value: "true"},
	}}
	meta := metaFromBuildInfo(info, "v1.100.2", buildStamps{})
	wantShort := developmentVersion("2026-07-27T12:34:56Z")
	if got, want := meta.Short, wantShort; got != want {
		t.Fatalf("Short = %q, want %q", got, want)
	}
	if got, want := meta.Long, wantShort+"-t012345678-dirty"; got != want {
		t.Fatalf("Long = %q, want %q", got, want)
	}
	if got, want := meta.GitCommit, "0123456789abcdef"; got != want {
		t.Fatalf("GitCommit = %q, want %q", got, want)
	}
	if !meta.GitDirty {
		t.Fatal("GitDirty = false, want true")
	}
	if got, want := meta.TailscaleVersion, "v1.100.2"; got != want {
		t.Fatalf("TailscaleVersion = %q, want %q", got, want)
	}
}

func TestMetaFromBuildStamps(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "ignored"},
		{Key: "vcs.time", Value: "2026-07-27T12:34:56Z"},
		{Key: "vcs.modified", Value: "true"},
	}}
	meta := metaFromBuildInfo(info, "v1.100.2", buildStamps{
		short:  "v0.1.7",
		long:   "v0.1.7-t012345678",
		commit: "0123456789abcdef",
	})
	if got, want := meta.Short, "v0.1.7"; got != want {
		t.Fatalf("Short = %q, want %q", got, want)
	}
	if got, want := meta.Long, "v0.1.7-t012345678"; got != want {
		t.Fatalf("Long = %q, want %q", got, want)
	}
	if got, want := meta.GitCommit, "0123456789abcdef"; got != want {
		t.Fatalf("GitCommit = %q, want %q", got, want)
	}
	if meta.GitDirty {
		t.Fatal("GitDirty = true for stamped build")
	}
}

func TestMetaString(t *testing.T) {
	tests := []struct {
		name string
		meta Meta
		want string
	}{
		{
			name: "clean",
			meta: Meta{
				Short:            "v0.1.7",
				Long:             "v0.1.7-t012345678",
				GitCommit:        "0123456789abcdef",
				TailscaleVersion: "v1.100.2",
			},
			want: "tailmix v0.1.7\n  commit: 0123456789abcdef\n  long version: v0.1.7-t012345678\n  tailscale: v1.100.2",
		},
		{
			name: "dirty",
			meta: Meta{
				Short:            "v0.1.7",
				Long:             "v0.1.7-t012345678-dirty",
				GitCommit:        "0123456789abcdef",
				GitDirty:         true,
				TailscaleVersion: "v1.100.2",
			},
			want: "tailmix v0.1.7\n  commit: 0123456789abcdef-dirty\n  long version: v0.1.7-t012345678-dirty\n  tailscale: v1.100.2",
		},
		{
			name: "no build info",
			meta: Meta{
				Short:            "v0.1.0-dev.ERR-BuildInfo",
				Long:             "v0.1.0-dev.ERR-BuildInfo",
				TailscaleVersion: "v1.100.2",
			},
			want: "tailmix v0.1.0-dev.ERR-BuildInfo\n  long version: v0.1.0-dev.ERR-BuildInfo\n  tailscale: v1.100.2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.meta.String(); got != test.want {
				t.Fatalf("Meta.String() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMetaFormatNamesComponent(t *testing.T) {
	meta := Meta{
		Short:            "v0.1.7",
		Long:             "v0.1.7-t012345678",
		TailscaleVersion: "v1.100.2",
	}
	if got, want := meta.Format("tailmixd"), "tailmixd v0.1.7\n  long version: v0.1.7-t012345678\n  tailscale: v1.100.2"; got != want {
		t.Fatalf("Meta.Format() = %q, want %q", got, want)
	}
}
