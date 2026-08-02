package main

import (
	"errors"
	"reflect"
	"testing"

	"tailscale.com/cmd/tailscaled/childproc"
)

func TestRunChildProcess(t *testing.T) {
	const mode = "tailmix-test-child"
	wantErr := errors.New("child result")
	var gotArgs []string
	childproc.Add(mode, func(args []string) error {
		gotArgs = args
		return wantErr
	})
	defer delete(childproc.Code, mode)

	handled, err := runChildProcess([]string{"be-child", mode, "one", "two"})
	if !handled {
		t.Fatal("registered child process was not handled")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("child error = %v, want %v", err, wantErr)
	}
	if wantArgs := []string{"one", "two"}; !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("child args = %q, want %q", gotArgs, wantArgs)
	}
}

func TestRunChildProcessIgnoresDaemonArguments(t *testing.T) {
	handled, err := runChildProcess([]string{"--version"})
	if handled || err != nil {
		t.Fatalf("runChildProcess handled daemon arguments: handled=%v err=%v", handled, err)
	}
}

func TestRunChildProcessRejectsInvalidMode(t *testing.T) {
	for _, args := range [][]string{{"be-child"}, {"be-child", "unknown-tailmix-child"}} {
		handled, err := runChildProcess(args)
		if !handled || err == nil {
			t.Errorf("runChildProcess(%q) = handled %v, err %v; want handled error", args, handled, err)
		}
	}
}
