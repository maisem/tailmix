package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyVerifiesAndAtomicallyInstallsPair(t *testing.T) {
	archive := tarball(t, map[string]string{"nested/tailmix": "client", "nested/tailmixd": "daemon", "README": "ignored"})
	sum := sha256.Sum256(archive)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.2.0","assets":[{"name":"tailmix_1.2.0_linux_amd64.tar.gz","browser_download_url":"%s/archive"},{"name":"checksums.txt","browser_download_url":"%s/sums"}]}`, server.URL, server.URL)
		case "/archive":
			_, _ = w.Write(archive)
		case "/sums":
			fmt.Fprintf(w, "%x  tailmix_1.2.0_linux_amd64.tar.gz\n", sum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	oldDir := filepath.Join(root, "versions", "v1.0.0")
	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"tailmix", "tailmixd"} {
		if err := os.WriteFile(filepath.Join(oldDir, n), []byte("old"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("versions/v1.0.0", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	c := Client{APIURL: server.URL + "/latest", Root: root, GOOS: "linux", GOARCH: "amd64"}
	r, old, updated, err := c.Apply(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !updated || r.Version != "v1.2.0" || old != "versions/v1.0.0" {
		t.Fatalf("Apply = %#v, %q, %v", r, old, updated)
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if target != "versions/v1.2.0" {
		t.Fatalf("current = %q", target)
	}
	for n, want := range map[string]string{"tailmix": "client", "tailmixd": "daemon"} {
		got, err := os.ReadFile(filepath.Join(root, target, n))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", n, got, err)
		}
	}
	info, err := os.Stat(filepath.Join(root, target))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("version directory mode = %v", info.Mode().Perm())
	}
	if err := c.Rollback(old); err != nil {
		t.Fatal(err)
	}
	target, _ = os.Readlink(filepath.Join(root, "current"))
	if target != old {
		t.Fatalf("rollback current = %q", target)
	}
}

func TestInstallRejectsBadChecksumWithoutChangingCurrent(t *testing.T) {
	archive := tarball(t, map[string]string{"tailmix": "a", "tailmixd": "b"})
	srv := assetServer(t, archive, []byte("0000  release.tar.gz\n"))
	defer srv.Close()
	root := t.TempDir()
	if err := os.Symlink("versions/old", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	c := Client{Root: root, GOOS: "linux"}
	_, err := c.Install(context.Background(), Release{Version: "v2.0.0", ArchiveName: "release.tar.gz", ArchiveURL: srv.URL + "/archive", ChecksumsURL: srv.URL + "/sums"})
	if err == nil {
		t.Fatal("Install succeeded with bad checksum")
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if target != "versions/old" {
		t.Fatalf("current changed to %q", target)
	}
}

func TestInstallRequiresBothBinaries(t *testing.T) {
	archive := tarball(t, map[string]string{"tailmix": "a"})
	sum := sha256.Sum256(archive)
	srv := assetServer(t, archive, []byte(fmt.Sprintf("%x  release.tar.gz\n", sum)))
	defer srv.Close()
	c := Client{Root: t.TempDir(), GOOS: "linux"}
	_, err := c.Install(context.Background(), Release{Version: "v2.0.0", ArchiveName: "release.tar.gz", ArchiveURL: srv.URL + "/archive", ChecksumsURL: srv.URL + "/sums"})
	if err == nil {
		t.Fatal("Install succeeded without tailmixd")
	}
}

func TestRecoverCleansInterruptedArtifacts(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "versions", ".stage-dead")
	if err := os.MkdirAll(stage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("versions/new", filepath.Join(root, ".current.new")); err != nil {
		t.Fatal(err)
	}
	if err := (Client{Root: root}).Recover(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{stage, filepath.Join(root, ".current.new")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s remains", p)
		}
	}
}

func TestNewerUsesSemanticVersions(t *testing.T) {
	newer, err := Newer("1.9.0", "v1.10.0")
	if err != nil || !newer {
		t.Fatalf("Newer = %v, %v", newer, err)
	}
	newer, err = Newer("1.10.0", "v1.10.0")
	if err != nil || newer {
		t.Fatalf("equal Newer = %v, %v", newer, err)
	}
}

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func assetServer(t *testing.T, archive, sums []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/archive" {
			_, _ = w.Write(archive)
		} else if r.URL.Path == "/sums" {
			_, _ = w.Write(sums)
		} else {
			http.NotFound(w, r)
		}
	}))
}
