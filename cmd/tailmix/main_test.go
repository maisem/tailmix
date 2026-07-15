package main

import (
	"bytes"
	"testing"
)

func TestStatusRequiresJSONFlagForMachineReadableOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"profiles"`)) {
		t.Fatalf("status JSON missing profiles: %s", stdout.String())
	}
}

func TestShortDNSLookupIsRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"resolve", "db"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected short-name resolve to fail")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("unqualified")) {
		t.Fatalf("stderr = %s", stderr.String())
	}
}
