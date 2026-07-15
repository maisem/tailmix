package main

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"

	"github.com/maisem/tailmix/profilesocket"
)

func TestProfileSelectsLocalAPISocketForUpstreamCLI(t *testing.T) {
	socketDir := t.TempDir()
	t.Setenv(profilesocket.EnvDir, socketDir)
	var gotArgs []string
	runner := func(_ context.Context, args []string) error {
		gotArgs = slices.Clone(args)
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"work", "status", "--json"}, &stdout, &stderr, runner); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	wantSocket, err := profilesocket.Path(socketDir, "work")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--socket=" + wantSocket, "status", "--json"}
	if !slices.Equal(gotArgs, want) {
		t.Fatalf("upstream CLI args = %q, want %q", gotArgs, want)
	}
}

func TestProfileCLIRejectsSocketOverride(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"work", "--socket=/tmp/other", "status"}, io.Discard, &stderr, func(context.Context, []string) error {
		t.Fatal("upstream CLI unexpectedly called")
		return nil
	})
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("managed by tailmix")) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}
