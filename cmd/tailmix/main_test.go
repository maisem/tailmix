package main

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profilesocket"
)

type fakeManagementClient struct {
	profile       controlapi.Profile
	profileName   string
	ipPatch       controlapi.PatchIPRoutesRequest
	dnsPatch      controlapi.PatchDNSRoutesRequest
	searchReplace []string
}

func (f *fakeManagementClient) Profiles(context.Context, bool) (controlapi.Profiles, error) {
	return controlapi.Profiles{Profiles: []controlapi.Profile{f.profile}}, nil
}
func (f *fakeManagementClient) Profile(_ context.Context, name string) (controlapi.Profile, error) {
	f.profileName = name
	return f.profile, nil
}
func (f *fakeManagementClient) AddProfile(context.Context, controlapi.AddProfileRequest) (controlapi.Profile, error) {
	return f.profile, nil
}
func (f *fakeManagementClient) PatchProfile(context.Context, string, controlapi.PatchProfileRequest) (controlapi.Profile, error) {
	return f.profile, nil
}
func (f *fakeManagementClient) ProfileAction(context.Context, string, string) (controlapi.Profile, error) {
	return f.profile, nil
}
func (f *fakeManagementClient) RemoveProfile(context.Context, string, bool) (controlapi.Profile, error) {
	return f.profile, nil
}
func (f *fakeManagementClient) IPRoutes(context.Context, bool) (controlapi.IPRoutes, error) {
	return controlapi.IPRoutes{}, nil
}
func (f *fakeManagementClient) PatchIPRoutes(_ context.Context, request controlapi.PatchIPRoutesRequest) (controlapi.IPRoutes, error) {
	f.ipPatch = request
	return controlapi.IPRoutes{}, nil
}
func (f *fakeManagementClient) DNSRoutes(context.Context, bool) (controlapi.DNSRoutes, error) {
	return controlapi.DNSRoutes{}, nil
}
func (f *fakeManagementClient) PatchDNSRoutes(_ context.Context, request controlapi.PatchDNSRoutesRequest) (controlapi.DNSRoutes, error) {
	f.dnsPatch = request
	return controlapi.DNSRoutes{}, nil
}
func (f *fakeManagementClient) SearchDomains(context.Context) (controlapi.SearchDomains, error) {
	return controlapi.SearchDomains{}, nil
}
func (f *fakeManagementClient) ReplaceSearchDomains(_ context.Context, desired []string) (controlapi.SearchDomains, error) {
	f.searchReplace = slices.Clone(desired)
	return controlapi.SearchDomains{Desired: desired}, nil
}
func (f *fakeManagementClient) PatchSearchDomains(context.Context, controlapi.PatchSearchDomainsRequest) (controlapi.SearchDomains, error) {
	return controlapi.SearchDomains{}, nil
}
func (f *fakeManagementClient) ClearSearchDomains(context.Context) (controlapi.SearchDomains, error) {
	return controlapi.SearchDomains{}, nil
}

func testDependencies(client managementClient, stdout, stderr io.Writer, runner cliRunner) dependencies {
	return dependencies{
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: stderr,
		runCLI: runner,
		newClient: func(string) managementClient {
			return client
		},
	}
}

func TestTSSelectsOpaqueProfileLocalAPISocket(t *testing.T) {
	socketDir := t.TempDir()
	client := &fakeManagementClient{profile: controlapi.Profile{ID: "p_012345", Name: "work"}}
	var gotArgs []string
	runner := func(_ context.Context, args []string) error {
		gotArgs = slices.Clone(args)
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"--socket-dir", socketDir, "ts", "--profile", "work", "status", "--json"},
		testDependencies(client, &stdout, &stderr, runner))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	wantSocket, err := profilesocket.Path(socketDir, "p_012345")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--socket=" + wantSocket, "status", "--json"}
	if !slices.Equal(gotArgs, want) {
		t.Fatalf("upstream CLI args = %q, want %q", gotArgs, want)
	}
	if client.profileName != "work" {
		t.Fatalf("profile selector = %q, want work", client.profileName)
	}
}

func TestTSRejectsSocketOverride(t *testing.T) {
	client := &fakeManagementClient{}
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"ts", "--profile", "work", "--socket=/tmp/other", "status"},
		testDependencies(client, io.Discard, &stderr, func(context.Context, []string) error {
			t.Fatal("upstream CLI unexpectedly called")
			return nil
		}))
	if code != 2 || !bytes.Contains(stderr.Bytes(), []byte("managed by tailmix")) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestTSLeavesUpstreamProfileArgumentsUntouched(t *testing.T) {
	client := &fakeManagementClient{profile: controlapi.Profile{ID: "p_work", Name: "work", LocalAPISocket: "/tmp/work.sock"}}
	var gotArgs []string
	code := runWithDependencies(context.Background(),
		[]string{"ts", "--profile", "work", "switch", "--profile", "upstream-profile"},
		testDependencies(client, io.Discard, io.Discard, func(_ context.Context, args []string) error {
			gotArgs = slices.Clone(args)
			return nil
		}))
	want := []string{"--socket=/tmp/work.sock", "switch", "--profile", "upstream-profile"}
	if code != 0 || !slices.Equal(gotArgs, want) {
		t.Fatalf("exit = %d, upstream args = %q, want %q", code, gotArgs, want)
	}
}

func TestLegacySyntaxExplainsReplacement(t *testing.T) {
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"work", "status"},
		testDependencies(&fakeManagementClient{}, io.Discard, &stderr, nil))
	if code != 2 || !strings.Contains(stderr.String(), "tailmix ts --profile work status") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRootHelpShowsFullSubcommandSpace(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"help"},
		testDependencies(&fakeManagementClient{}, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	for _, command := range []string{"profiles", "routes", "dns routes", "dns search", "tailscale", "ts"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help does not contain %q:\n%s", command, stdout.String())
		}
	}
}

func TestRouteBindingAndAcceptAllRequests(t *testing.T) {
	client := &fakeManagementClient{}
	code := runWithDependencies(context.Background(),
		[]string{"routes", "bind", "--profile", "work", "10.20.3.4/16", "2001:db8::1/64"},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 {
		t.Fatalf("bind exit code = %d", code)
	}
	wantPrefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8::/64")}
	for i, want := range wantPrefixes {
		if client.ipPatch.Bind[i].Prefix != want || client.ipPatch.Bind[i].ProfileName != "work" {
			t.Fatalf("binding %d = %+v, want %v -> work", i, client.ipPatch.Bind[i], want)
		}
	}

	code = runWithDependencies(context.Background(),
		[]string{"routes", "set", "--profile", "work", "--accept-all=true"},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 || !client.ipPatch.AcceptAll["work"] {
		t.Fatalf("accept-all exit = %d, request = %+v", code, client.ipPatch)
	}
}

func TestDNSUsesTailscaleDNSNameCanonicalization(t *testing.T) {
	client := &fakeManagementClient{}
	code := runWithDependencies(context.Background(),
		[]string{"dns", "routes", "bind", "--profile", "work", ".Corp.Example.COM."},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 {
		t.Fatalf("DNS bind exit code = %d", code)
	}
	if got := client.dnsPatch.Bind[0].Domain; got != "corp.example.com" {
		t.Fatalf("canonical domain = %q", got)
	}

	code = runWithDependencies(context.Background(),
		[]string{"dns", "search", "set", "Work.Example.COM.", "lab.example.com"},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 || !slices.Equal(client.searchReplace, []string{"work.example.com", "lab.example.com"}) {
		t.Fatalf("search exit = %d, domains = %q", code, client.searchReplace)
	}

	var stderr bytes.Buffer
	code = runWithDependencies(context.Background(),
		[]string{"dns", "search", "set", "bad..example.com"},
		testDependencies(client, io.Discard, &stderr, nil))
	if code != 2 || !strings.Contains(stderr.String(), "invalid DNS domain") {
		t.Fatalf("invalid domain exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestRouteHelpDocumentsOverrides(t *testing.T) {
	for _, help := range []string{routesHelp, dnsRoutesHelp} {
		if !strings.Contains(help, "explicit overrides") || !strings.Contains(help, "accept-all") {
			t.Fatalf("route help does not explain precedence:\n%s", help)
		}
	}
}
