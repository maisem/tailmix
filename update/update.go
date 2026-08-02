// Package update installs paired tailmix releases published by GoReleaser.
package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const defaultAPIURL = "https://api.github.com/repos/maisem/tailmix/releases/latest"

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type Client struct {
	HTTP                       HTTPDoer
	APIURL, Root, GOOS, GOARCH string
}
type Release struct{ Version, ArchiveURL, ArchiveName, ChecksumsURL string }
type githubAsset struct{ Name, BrowserDownloadURL string }
type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

func (a *githubAsset) UnmarshalJSON(b []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	if err := json.Unmarshal(fields["name"], &a.Name); err != nil {
		return err
	}
	return json.Unmarshal(fields["browser_download_url"], &a.BrowserDownloadURL)
}

func (c Client) defaults() Client {
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 10 * time.Minute}
	}
	if c.APIURL == "" {
		c.APIURL = defaultAPIURL
	}
	if c.GOOS == "" {
		c.GOOS = runtime.GOOS
	}
	if c.GOARCH == "" {
		c.GOARCH = runtime.GOARCH
	}
	return c
}

// Latest returns the latest stable release and its platform assets.
func (c Client) Latest(ctx context.Context) (Release, error) {
	c = c.defaults()
	var gr githubRelease
	if err := c.getJSON(ctx, c.APIURL, &gr); err != nil {
		return Release{}, err
	}
	if gr.Draft || gr.Prerelease || !semver.IsValid(gr.TagName) {
		return Release{}, fmt.Errorf("latest release has invalid stable tag %q", gr.TagName)
	}
	suffix := ".tar.gz"
	if c.GOOS == "windows" {
		suffix = ".zip"
	}
	needle := "_" + c.GOOS + "_" + c.GOARCH
	r := Release{Version: gr.TagName}
	for _, a := range gr.Assets {
		switch {
		case a.Name == "checksums.txt" || strings.HasSuffix(a.Name, "_checksums.txt"):
			r.ChecksumsURL = a.BrowserDownloadURL
		case strings.Contains(a.Name, needle) && strings.HasSuffix(a.Name, suffix):
			if r.ArchiveURL != "" {
				return Release{}, fmt.Errorf("release has multiple archives for %s/%s", c.GOOS, c.GOARCH)
			}
			r.ArchiveURL, r.ArchiveName = a.BrowserDownloadURL, a.Name
		}
	}
	if r.ArchiveURL == "" || r.ChecksumsURL == "" {
		return Release{}, fmt.Errorf("release %s lacks archive or checksums for %s/%s", gr.TagName, c.GOOS, c.GOARCH)
	}
	return r, nil
}

// Newer reports whether latest is newer than current. Current may omit v.
func Newer(current, latest string) (bool, error) {
	if !strings.HasPrefix(current, "v") {
		current = "v" + current
	}
	if !semver.IsValid(current) || !semver.IsValid(latest) {
		return false, fmt.Errorf("invalid versions %q and %q", current, latest)
	}
	return semver.Compare(latest, current) > 0, nil
}

// Check returns the latest release and whether it is newer than current.
func (c Client) Check(ctx context.Context, current string) (Release, bool, error) {
	r, err := c.Latest(ctx)
	if err != nil {
		return Release{}, false, err
	}
	newer, err := Newer(current, r.Version)
	return r, newer, err
}

// Apply checks and installs the latest release when it is newer.
func (c Client) Apply(ctx context.Context, current string) (Release, string, bool, error) {
	r, newer, err := c.Check(ctx, current)
	if err != nil || !newer {
		return r, "", false, err
	}
	old, err := c.Install(ctx, r)
	return r, old, err == nil, err
}

// Install verifies, stages, and atomically activates r. The returned prior
// symlink target can be supplied to Rollback.
func (c Client) Install(ctx context.Context, r Release) (string, error) {
	c = c.defaults()
	if c.Root == "" {
		return "", errors.New("update root is required")
	}
	if !semver.IsValid(r.Version) {
		return "", fmt.Errorf("invalid release version %q", r.Version)
	}
	archive, err := c.get(ctx, r.ArchiveURL)
	if err != nil {
		return "", err
	}
	sums, err := c.get(ctx, r.ChecksumsURL)
	if err != nil {
		return "", err
	}
	if err := verifyChecksum(r.ArchiveName, archive, sums); err != nil {
		return "", err
	}
	if err := c.Recover(); err != nil {
		return "", err
	}
	versions := filepath.Join(c.Root, "versions")
	if err := os.MkdirAll(versions, 0755); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(versions, ".stage-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := extractPair(stage, r.ArchiveName, archive); err != nil {
		return "", err
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return "", err
	}
	if err := syncTree(stage); err != nil {
		return "", err
	}
	dest := filepath.Join(versions, r.Version)
	if _, err := os.Stat(dest); err == nil {
		if err := validatePair(dest, c.GOOS); err != nil {
			return "", fmt.Errorf("existing version: %w", err)
		}
		_ = os.RemoveAll(stage)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect version destination: %w", err)
	} else if err := os.Rename(stage, dest); err != nil {
		return "", fmt.Errorf("publish version: %w", err)
	}
	if err := syncDir(versions); err != nil {
		return "", err
	}
	old, err := os.Readlink(filepath.Join(c.Root, "current"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := switchLink(c.Root, filepath.Join("versions", r.Version)); err != nil {
		return "", err
	}
	keep = true
	return old, nil
}

func (c Client) Rollback(target string) error {
	c = c.defaults()
	if c.Root == "" || target == "" {
		return errors.New("update root and rollback target are required")
	}
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("rollback target escapes update root")
	}
	if err := validatePair(filepath.Join(c.Root, clean), c.GOOS); err != nil {
		return err
	}
	return switchLink(c.Root, clean)
}

// Recover removes artifacts left by interrupted staging or link replacement.
func (c Client) Recover() error {
	if c.Root == "" {
		return errors.New("update root is required")
	}
	ents, err := os.ReadDir(filepath.Join(c.Root, "versions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".stage-") {
			if err := os.RemoveAll(filepath.Join(c.Root, "versions", e.Name())); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(filepath.Join(c.Root, ".current.new")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c Client) getJSON(ctx context.Context, url string, out any) error {
	b, err := c.get(ctx, url)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode release: %w", err)
	}
	return nil
}
func (c Client) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "tailmix-updater")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func verifyChecksum(name string, data, sums []byte) error {
	want := ""
	s := bufio.NewScanner(bytes.NewReader(sums))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			want = f[0]
			break
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	if want == "" {
		return fmt.Errorf("checksum for %q not found", name)
	}
	got := sha256.Sum256(data)
	if !strings.EqualFold(want, hex.EncodeToString(got[:])) {
		return fmt.Errorf("checksum mismatch for %q", name)
	}
	return nil
}

func extractPair(dir, name string, data []byte) error {
	wanted := map[string]bool{"tailmix": false, "tailmixd": false}
	if strings.HasSuffix(name, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		for _, f := range zr.File {
			base := strings.TrimSuffix(filepath.Base(f.Name), ".exe")
			if _, yes := wanted[base]; !yes || f.FileInfo().IsDir() {
				continue
			}
			if wanted[base] {
				return fmt.Errorf("duplicate %s", base)
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			err = writeBinary(dir, base+".exe", rc)
			closeErr := rc.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			wanted[base] = true
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			base := filepath.Base(h.Name)
			if _, yes := wanted[base]; !yes || h.Typeflag != tar.TypeReg {
				continue
			}
			if wanted[base] {
				return fmt.Errorf("duplicate %s", base)
			}
			if err := writeBinary(dir, base, tr); err != nil {
				return err
			}
			wanted[base] = true
		}
	}
	for n, found := range wanted {
		if !found {
			return fmt.Errorf("archive lacks %s", n)
		}
	}
	return nil
}

func writeBinary(dir, name string, r io.Reader) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, io.LimitReader(r, 128<<20)); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
func validatePair(dir, goos string) error {
	suffix := ""
	if goos == "windows" {
		suffix = ".exe"
	}
	for _, n := range []string{"tailmix" + suffix, "tailmixd" + suffix} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return nil
}
func syncTree(dir string) error { return syncDir(dir) }
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func switchLink(root, target string) error {
	tmp := filepath.Join(root, ".current.new")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(root)
}
