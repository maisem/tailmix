package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profilesocket"
)

type fakeManagementClient struct {
	profile        controlapi.Profile
	profileName    string
	ipPatch        controlapi.PatchIPRoutesRequest
	dnsPatch       controlapi.PatchDNSRoutesRequest
	searchReplace  []string
	statusProfiles []controlapi.Profile
}

func (f *fakeManagementClient) Profiles(context.Context, bool) (controlapi.Profiles, error) {
	if f.statusProfiles != nil {
		return controlapi.Profiles{Profiles: f.statusProfiles}, nil
	}
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

func TestTSForwardsNativeLoginServer(t *testing.T) {
	client := &fakeManagementClient{
		profile: controlapi.Profile{ID: "p_work", Name: "work", LocalAPISocket: "/tmp/work.sock"},
	}
	var gotArgs []string
	code := runWithDependencies(context.Background(),
		[]string{"ts", "--profile", "work", "login", "--login-server=https://headscale.example.com"},
		testDependencies(client, io.Discard, io.Discard, func(_ context.Context, args []string) error {
			gotArgs = slices.Clone(args)
			return nil
		}))
	want := []string{
		"--socket=/tmp/work.sock",
		"login",
		"--login-server=https://headscale.example.com",
	}
	if code != 0 || !slices.Equal(gotArgs, want) {
		t.Fatalf("exit = %d, upstream args = %q, want %q", code, gotArgs, want)
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
	for _, command := range []string{"status", "profiles", "routes", "dns routes", "dns search", "tailscale", "ts"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help does not contain %q:\n%s", command, stdout.String())
		}
	}
}

func TestProfilesHelpOmitsControlURL(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"profiles", "help"},
		testDependencies(&fakeManagementClient{}, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.Contains(stdout.String(), "control-url") {
		t.Fatalf("profiles help still contains control-url:\n%s", stdout.String())
	}
}

func TestStatusShowsActiveProfilesOnly(t *testing.T) {
	client := &fakeManagementClient{
		statusProfiles: []controlapi.Profile{{
			ID: "work-id", Name: "work", Enabled: true, RuntimeState: "running",
			MagicDNSSuffix: "corp.example", PeerCount: 3,
		}},
	}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"status"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"PROFILE", "work", "running", "corp.example"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("status does not contain %q:\n%s", want, stdout.String())
		}
	}
	for _, unwanted := range []string{"IP ROUTES", "DNS ROUTES", "DNS SEARCH"} {
		if strings.Contains(stdout.String(), unwanted) {
			t.Errorf("status unexpectedly contains %q:\n%s", unwanted, stdout.String())
		}
	}
}

func TestStatusJSONMatchesProfilesList(t *testing.T) {
	client := &fakeManagementClient{
		statusProfiles: []controlapi.Profile{{ID: "work-id", Name: "work"}},
	}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"status", "--json"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var got controlapi.Profiles
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "work" {
		t.Fatalf("status JSON = %+v", got)
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

func TestDefaultIPRouteListIncludesEveryDetectedRoute(t *testing.T) {
	boundPrefix := netip.MustParsePrefix("10.1.0.0/16")
	advertisedPrefix := netip.MustParsePrefix("10.0.0.0/8")
	routes := controlapi.IPRoutes{
		Bindings: []controlapi.IPRouteBinding{{
			Prefix: boundPrefix, ProfileID: "work-id", ProfileName: "work", Policy: "bound",
			PrimaryRouter: "work-router", State: "installed",
			CoveringRoute: advertisedPrefix,
		}},
		Available: []controlapi.AvailableIPRoute{
			{Prefix: advertisedPrefix, ProfileID: "work-id", ProfileName: "work", PrimaryRouter: "work-router"},
			{Prefix: advertisedPrefix, ProfileID: "work-id", ProfileName: "work", PrimaryRouter: "backup-router"},
			{Prefix: advertisedPrefix, ProfileID: "lab-id", ProfileName: "lab", PrimaryRouter: "lab-router"},
			{Prefix: netip.MustParsePrefix("172.16.0.0/12"), ProfileID: "lab-id", ProfileName: "lab", PrimaryRouter: "lab-router"},
		},
	}
	var output bytes.Buffer
	writeIPRoutes(&output, routes, false)
	var detectedRows int
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, advertisedPrefix.String()+" ") {
			detectedRows++
		}
	}
	if got := detectedRows; got != 3 {
		t.Fatalf("detected route appears in %d rows, want all three advertisers:\n%s", got, output.String())
	}
	for _, want := range []string{
		"STATE", "MATCHED ROUTE", "172.16.0.0/12", advertisedPrefix.String(),
		"✓", "lab-router", "backup-router",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("IP route list does not contain %q:\n%s", want, output.String())
		}
	}
	for _, unwanted := range []string{
		"POLICY", "ENABLED", "STATUS", "OVERRIDDEN BY",
		"detected", "installed", "available",
	} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("IP route list unexpectedly contains %q:\n%s", unwanted, output.String())
		}
	}
}

func TestDefaultDNSRouteListIncludesEveryDetectedRoute(t *testing.T) {
	routes := controlapi.DNSRoutes{
		Automatic: []controlapi.DNSRouteBinding{{
			Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
			Source: "magicdns", Policy: "automatic", State: "installed",
		}},
		Available: []controlapi.AvailableDNSRoute{
			{
				Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
				Source: "magicdns",
			},
			{
				Domain: "corp.example", ProfileID: "lab-id", ProfileName: "lab",
				Source: "split-dns", Resolvers: []controlapi.DNSResolver{{Addr: "10.0.0.54"}},
			},
			{
				Domain: "dev.example", ProfileID: "lab-id", ProfileName: "lab",
				Source: "split-dns", Resolvers: []controlapi.DNSResolver{{Addr: "10.0.0.53"}},
			},
		},
	}
	var output bytes.Buffer
	writeDNSRoutes(&output, routes, false)
	if got := strings.Count(output.String(), "corp.example"); got != 2 {
		t.Fatalf("domain appears %d times, want selected and other-profile detection:\n%s", got, output.String())
	}
	for _, want := range []string{
		"STATE", "RESOLVERS", "dev.example", "✓", "split-dns",
		"10.0.0.53", "10.0.0.54",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("DNS route list does not contain %q:\n%s", want, output.String())
		}
	}
	for _, unwanted := range []string{
		"POLICY", "ENABLED", "STATUS", "OVERRIDDEN BY",
		"detected", "automatic", "installed", "available",
	} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("DNS route list unexpectedly contains %q:\n%s", unwanted, output.String())
		}
	}
}

func TestSearchListIncludesEveryDetectedSearchDomain(t *testing.T) {
	domains := controlapi.SearchDomains{
		Desired: []string{"corp.example"},
		Installed: []controlapi.InstalledSearchDomain{{
			Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
		}},
		Available: []controlapi.AvailableSearchDomain{
			{Domain: "corp.example", ProfileID: "work-id", ProfileName: "work"},
			{Domain: "corp.example", ProfileID: "lab-id", ProfileName: "lab"},
			{Domain: "dev.example", ProfileID: "lab-id", ProfileName: "lab"},
		},
	}
	var output bytes.Buffer
	writeSearchDomains(&output, domains)
	if got := strings.Count(output.String(), "corp.example"); got != 2 {
		t.Fatalf("search domain appears %d times, want selected and other-profile detection:\n%s", got, output.String())
	}
	for _, want := range []string{"STATE", "dev.example", "✓", "lab"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("search domain list does not contain %q:\n%s", want, output.String())
		}
	}
	for _, unwanted := range []string{"ENABLED", "STATUS", "installed", "available"} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("search domain list unexpectedly contains %q:\n%s", unwanted, output.String())
		}
	}
}
