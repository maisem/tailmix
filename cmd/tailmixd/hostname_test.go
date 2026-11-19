package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/state"
)

func newAddProfileRequest(name string, disabled bool) controlapi.AddProfileRequest {
	return controlapi.AddProfileRequest{Name: name, Disabled: disabled}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func stubHostname(t *testing.T, name string, err error) {
	t.Helper()
	old := osHostname
	osHostname = func() (string, error) { return name, err }
	t.Cleanup(func() { osHostname = old })
}

func TestSanitizeHostname(t *testing.T) {
	for _, test := range []struct{ in, want string }{
		{"david-laptop-fedora", "david-laptop-fedora"},
		{"MyHost", "myhost"},
		{"laptop.example.com", "laptop"},
		{"  LAPTOP.local  ", "laptop"},
		{"My_Host", "my-host"},
		{"", ""},
		{"   ", ""},
		{"!!!", ""},
		{"a...b", "a"},
	} {
		if got := sanitizeHostname(test.in); got != test.want {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestDefaultHostnameUsesOSHostname(t *testing.T) {
	stubHostname(t, "TestBox.Example.COM", nil)
	if got, want := defaultHostname(), "testbox"; got != want {
		t.Fatalf("defaultHostname() = %q, want %q", got, want)
	}
}

func TestDefaultHostnameEmptyWhenUnavailable(t *testing.T) {
	stubHostname(t, "", errors.New("no hostname"))
	if got := defaultHostname(); got != "" {
		t.Fatalf("defaultHostname() = %q, want empty on error", got)
	}
	stubHostname(t, "!!!", nil)
	if got := defaultHostname(); got != "" {
		t.Fatalf("defaultHostname() = %q, want empty when unsanitizable", got)
	}
}

func TestResolveProfilesDefaultsHostnameToOSHostname(t *testing.T) {
	stubHostname(t, "TestHost.example.com", nil)
	statePath := filepath.Join(t.TempDir(), "state.json")
	got, err := resolveProfiles(state.State{}, []profileSpec{{ID: "home"}}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("profile count = %d, want 1", len(got))
	}
	if got[0].State.Hostname != "testhost" {
		t.Fatalf("hostname = %q, want %q", got[0].State.Hostname, "testhost")
	}
}

func TestResolveProfilesFallsBackWhenOSHostnameUnavailable(t *testing.T) {
	stubHostname(t, "", errors.New("no hostname"))
	statePath := filepath.Join(t.TempDir(), "state.json")
	got, err := resolveProfiles(state.State{}, []profileSpec{{ID: "home"}}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("profile count = %d, want 1", len(got))
	}
	if got[0].State.Hostname != "tailmix-home" {
		t.Fatalf("hostname = %q, want %q", got[0].State.Hostname, "tailmix-home")
	}
}

func TestAddProfileDefaultsHostnameToOSHostname(t *testing.T) {
	stubHostname(t, "MyLaptop.example.com", nil)
	s := newLifecycleTestSupervisor(t, lifecycleTestState())
	got, err := s.AddProfile(testContext(t), newAddProfileRequest("lab", true))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "mylaptop" {
		t.Fatalf("hostname = %q, want %q", got.Hostname, "mylaptop")
	}
}

func TestAddProfileFallsBackWhenOSHostnameUnavailable(t *testing.T) {
	stubHostname(t, "", errors.New("no hostname"))
	s := newLifecycleTestSupervisor(t, lifecycleTestState())
	got, err := s.AddProfile(testContext(t), newAddProfileRequest("lab", true))
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname == "" || got.Hostname == "mylaptop" {
		t.Fatalf("hostname = %q, want generated fallback", got.Hostname)
	}
	if len(got.Hostname) < len("tailmix-")+1 || got.Hostname[:8] != "tailmix-" {
		t.Fatalf("hostname = %q, want tailmix- prefix", got.Hostname)
	}
}
