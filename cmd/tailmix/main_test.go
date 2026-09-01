package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profilesocket"
	tailmixversion "github.com/maisem/tailmix/version"
	"github.com/maisem/tailmix/wireguardcfg"
)

type fakeManagementClient struct {
	profile          controlapi.Profile
	profileName      string
	status           controlapi.Status
	daemonState      controlapi.DaemonState
	daemonUp         bool
	ipPatch          controlapi.PatchIPRoutesRequest
	exitSet          controlapi.SetExitNodeRequest
	exitCleared      bool
	exitNodes        controlapi.ExitNodes
	dnsPatch         controlapi.PatchDNSRoutesRequest
	searchReplace    []string
	statusProfiles   []controlapi.Profile
	serverVersion    tailmixversion.Meta
	versionErr       error
	updateStatus     controlapi.UpdateStatus
	updateAction     string
	wireGuardConfig  wireguardcfg.Config
	wireGuardSecrets wireguardcfg.Secrets
	wireGuardProfile controlapi.WireGuardProfile
	wireGuardName    string
	wireGuardShields bool
}

func (f *fakeManagementClient) Version(context.Context) (tailmixversion.Meta, error) {
	return f.serverVersion, f.versionErr
}
func (f *fakeManagementClient) Status(context.Context) (controlapi.Status, error) {
	return f.status, nil
}
func (f *fakeManagementClient) SetDaemonUp(_ context.Context, up bool) (controlapi.DaemonState, error) {
	f.daemonUp = up
	return f.daemonState, nil
}
func (f *fakeManagementClient) UpdateStatus(context.Context) (controlapi.UpdateStatus, error) {
	return f.updateStatus, nil
}
func (f *fakeManagementClient) UpdateAction(_ context.Context, action string) (controlapi.UpdateStatus, error) {
	f.updateAction = action
	return f.updateStatus, nil
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
func (f *fakeManagementClient) ExitNodes(context.Context) (controlapi.ExitNodes, error) {
	return f.exitNodes, nil
}
func (f *fakeManagementClient) SetExitNode(_ context.Context, request controlapi.SetExitNodeRequest) (controlapi.ExitNodes, error) {
	f.exitSet = request
	return f.exitNodes, nil
}
func (f *fakeManagementClient) ClearExitNode(context.Context) (controlapi.ExitNodes, error) {
	f.exitCleared = true
	return f.exitNodes, nil
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
func (f *fakeManagementClient) ApplyWireGuard(_ context.Context, config wireguardcfg.Config, secrets wireguardcfg.Secrets) (controlapi.WireGuardProfile, error) {
	f.wireGuardConfig = config
	f.wireGuardSecrets = secrets
	return f.wireGuardProfile, nil
}
func (f *fakeManagementClient) WireGuardProfile(_ context.Context, name string) (controlapi.WireGuardProfile, error) {
	f.wireGuardName = name
	return f.wireGuardProfile, nil
}
func (f *fakeManagementClient) SetWireGuardShieldsUp(_ context.Context, name string, enabled bool) (controlapi.WireGuardProfile, error) {
	f.wireGuardName = name
	f.wireGuardShields = enabled
	f.wireGuardProfile.ShieldsUp = enabled
	return f.wireGuardProfile, nil
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
		version: "tailmix test-version",
	}
}

func TestDaemonLifecycleCommands(t *testing.T) {
	for _, test := range []struct {
		command string
		up      bool
	}{
		{command: "up", up: true},
		{command: "down", up: false},
	} {
		t.Run(test.command, func(t *testing.T) {
			client := &fakeManagementClient{daemonState: controlapi.DaemonState{State: test.command}}
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{test.command},
				testDependencies(client, &stdout, &stderr, nil))
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if client.daemonUp != test.up {
				t.Fatalf("daemon up = %v, want %v", client.daemonUp, test.up)
			}
			if got, want := stdout.String(), "tailmix is "+test.command+".\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestDaemonLifecycleCommandsRejectArguments(t *testing.T) {
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"down", "now"},
		testDependencies(&fakeManagementClient{}, io.Discard, &stderr, nil))
	if code != 2 || !strings.Contains(stderr.String(), "unexpected arguments: now") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestUpdateCommands(t *testing.T) {
	for _, command := range []string{"status", "enable", "disable", "check", "apply"} {
		t.Run(command, func(t *testing.T) {
			client := &fakeManagementClient{updateStatus: controlapi.UpdateStatus{
				Enabled: true, CurrentVersion: "1.2.3", AvailableVersion: "1.2.4", State: "available",
			}}
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{"update", command},
				testDependencies(client, &stdout, &stderr, nil))
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if command == "status" {
				if client.updateAction != "" {
					t.Fatalf("action = %q", client.updateAction)
				}
			} else if client.updateAction != command {
				t.Fatalf("action = %q, want %q", client.updateAction, command)
			}
			if !strings.Contains(stdout.String(), "1.2.4") {
				t.Fatalf("output = %q", stdout.String())
			}
		})
	}
}

func TestUpdateStatusJSON(t *testing.T) {
	client := &fakeManagementClient{updateStatus: controlapi.UpdateStatus{Enabled: true, State: "idle"}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"update", "status", "--json"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var got controlapi.UpdateStatus
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.State != "idle" {
		t.Fatalf("status = %+v", got)
	}
}

func TestWireGuardApplyResolvesKeyFilesRelativeToManifest(t *testing.T) {
	dir := t.TempDir()
	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPrivate, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := peerPrivate.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte(private.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := "version: 1\nname: lab\ndnsSuffix: wg.example\naddresses: [10.0.0.1]\nprivateKeyFile: private.key\npeers:\n  - name: peer\n    publicKey: " + peerPublic.String() + "\n    addresses: [10.0.0.2]\n"
	manifestPath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{wireGuardProfile: controlapi.WireGuardProfile{Name: "lab", Kind: "wireguard"}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"wireguard", "apply", "--file", manifestPath},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if client.wireGuardConfig.Name != "lab" || client.wireGuardSecrets.PrivateKey == nil || *client.wireGuardSecrets.PrivateKey != private {
		t.Fatalf("apply request = config %+v, secrets %+v", client.wireGuardConfig, client.wireGuardSecrets)
	}
	if !strings.Contains(stdout.String(), "lab") || !strings.Contains(stdout.String(), "wireguard") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestWireGuardApplyReadsManifestFromStdin(t *testing.T) {
	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.Public()
	if err != nil {
		t.Fatal(err)
	}
	manifest := "version: 1\nname: lab\ndnsSuffix: wg.example\naddresses: [10.0.0.1]\npeers:\n  - name: peer\n    publicKey: " + public.String() + "\n    addresses: [10.0.0.2]\n"
	client := &fakeManagementClient{wireGuardProfile: controlapi.WireGuardProfile{Name: "lab"}}
	deps := testDependencies(client, io.Discard, io.Discard, nil)
	deps.stdin = strings.NewReader(manifest)
	if code := runWithDependencies(context.Background(), []string{"wireguard", "apply", "--file=-"}, deps); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if client.wireGuardConfig.Name != "lab" {
		t.Fatalf("config = %+v", client.wireGuardConfig)
	}
}

func TestWireGuardShieldsUp(t *testing.T) {
	client := &fakeManagementClient{wireGuardProfile: controlapi.WireGuardProfile{
		Name: "lab", Kind: "wireguard", PacketFilter: wireguardcfg.PacketFilter{Grants: []wireguardcfg.Grant{}},
	}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"wireguard", "shields-up", "lab", "on"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if client.wireGuardName != "lab" || !client.wireGuardShields || !strings.Contains(stdout.String(), "SHIELDS UP:") || !strings.Contains(stdout.String(), "yes") {
		t.Fatalf("name = %q, enabled = %v, stdout = %q", client.wireGuardName, client.wireGuardShields, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runWithDependencies(context.Background(), []string{"wireguard", "shields-up", "lab", "invalid"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 2 || !strings.Contains(stderr.String(), "must be on or off") {
		t.Fatalf("invalid state exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestWireGuardShowJSON(t *testing.T) {
	want := controlapi.WireGuardProfile{Name: "lab", Kind: "wireguard", PublicKey: "public", ListenPort: 51820}
	client := &fakeManagementClient{wireGuardProfile: want}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"wireguard", "show", "lab", "--json"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	var got controlapi.WireGuardProfile
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || got.Kind != want.Kind || got.PublicKey != want.PublicKey || got.ListenPort != want.ListenPort || client.wireGuardName != "lab" {
		t.Fatalf("profile = %+v, name = %q", got, client.wireGuardName)
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

func TestTSRejectsDelegationWhileDaemonDown(t *testing.T) {
	client := &fakeManagementClient{profile: controlapi.Profile{
		ID: "p_work", Name: "work", RuntimeState: "down",
	}}
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"ts", "--profile", "work", "status"},
		testDependencies(client, io.Discard, &stderr, func(context.Context, []string) error {
			t.Fatal("upstream CLI unexpectedly called")
			return nil
		}))
	if code != 1 || !strings.Contains(stderr.String(), "tailmix is down; run \"tailmix up\" first") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
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
		[]string{"ts", "-p", "work", "switch", "--profile", "upstream-profile"},
		testDependencies(client, io.Discard, io.Discard, func(_ context.Context, args []string) error {
			gotArgs = slices.Clone(args)
			return nil
		}))
	want := []string{"--socket=/tmp/work.sock", "switch", "--profile", "upstream-profile"}
	if code != 0 || !slices.Equal(gotArgs, want) {
		t.Fatalf("exit = %d, upstream args = %q, want %q", code, gotArgs, want)
	}
}

func TestShortProfileOption(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		gotProfile func(*fakeManagementClient) string
	}{
		{
			name: "tailscale delegation",
			args: []string{"ts", "-p", "work", "status"},
			gotProfile: func(client *fakeManagementClient) string {
				return client.profileName
			},
		},
		{
			name: "IP route bind",
			args: []string{"routes", "bind", "-p", "work", "10.20.0.0/16"},
			gotProfile: func(client *fakeManagementClient) string {
				if len(client.ipPatch.Bind) == 0 {
					return ""
				}
				return client.ipPatch.Bind[0].ProfileName
			},
		},
		{
			name: "IP route unbind",
			args: []string{"routes", "unbind", "10.20.0.0/16", "-p=work"},
			gotProfile: func(client *fakeManagementClient) string {
				if len(client.ipPatch.Unbind) == 0 {
					return ""
				}
				return client.ipPatch.Unbind[0].ProfileName
			},
		},
		{
			name: "IP route accept all",
			args: []string{"routes", "set", "-p", "work", "--accept-all=true"},
			gotProfile: func(client *fakeManagementClient) string {
				if _, ok := client.ipPatch.AcceptAll["work"]; ok {
					return "work"
				}
				return ""
			},
		},
		{
			name: "exit node",
			args: []string{"exit-node", "set", "-p", "work", "gateway"},
			gotProfile: func(client *fakeManagementClient) string {
				return client.exitSet.ProfileName
			},
		},
		{
			name: "DNS route bind",
			args: []string{"dns", "routes", "bind", "-p", "work", "corp.example"},
			gotProfile: func(client *fakeManagementClient) string {
				if len(client.dnsPatch.Bind) == 0 {
					return ""
				}
				return client.dnsPatch.Bind[0].ProfileName
			},
		},
		{
			name: "DNS route unbind",
			args: []string{"dns", "routes", "unbind", "corp.example", "-p=work"},
			gotProfile: func(client *fakeManagementClient) string {
				if len(client.dnsPatch.Unbind) == 0 {
					return ""
				}
				return client.dnsPatch.Unbind[0].ProfileName
			},
		},
		{
			name: "DNS route accept all",
			args: []string{"dns", "routes", "set", "-p", "work", "--accept-all=true"},
			gotProfile: func(client *fakeManagementClient) string {
				if _, ok := client.dnsPatch.AcceptAll["work"]; ok {
					return "work"
				}
				return ""
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeManagementClient{profile: controlapi.Profile{
				ID: "p_work", Name: "work", LocalAPISocket: "/tmp/work.sock",
			}}
			var stderr bytes.Buffer
			code := runWithDependencies(context.Background(), test.args,
				testDependencies(client, io.Discard, &stderr, func(context.Context, []string) error {
					return nil
				}))
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if got := test.gotProfile(client); got != "work" {
				t.Fatalf("profile = %q, want work", got)
			}
		})
	}
}

func TestProfileOptionRejectsMixedAliases(t *testing.T) {
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"routes", "bind", "-p", "work", "--profile", "home", "10.20.0.0/16"},
		testDependencies(&fakeManagementClient{}, io.Discard, &stderr, nil))
	if code != 2 || !strings.Contains(stderr.String(), "--profile may be specified only once") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
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
	for _, command := range []string{"status", "up", "down", "profiles", "routes", "exit-node", "dns routes", "dns search", "wireguard", "tailscale", "ts", "completion", "version"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help does not contain %q:\n%s", command, stdout.String())
		}
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell", "pwsh"} {
		t.Run(shell, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), []string{"completion", shell},
				testDependencies(&fakeManagementClient{}, &stdout, &stderr, nil))
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "completion __complete --") {
				t.Fatalf("completion script does not invoke tailmix's completion endpoint:\n%s", stdout.String())
			}
		})
	}
}

func TestCompletionSuggestsCommandsFlagsAndValues(t *testing.T) {
	client := &fakeManagementClient{statusProfiles: []controlapi.Profile{
		{Name: "home", RuntimeState: "running"},
		{Name: "work", RuntimeState: "disabled"},
	}}
	tests := []struct {
		name  string
		words []string
		want  []string
	}{
		{name: "root commands", words: []string{""}, want: []string{"up\t", "down\t", "profiles\t", "completion\t", "--socket-dir\t"}},
		{name: "subcommands", words: []string{"profiles", ""}, want: []string{"list\t", "rename\t", "help\t"}},
		{name: "update subcommands", words: []string{"update", ""}, want: []string{"status\t", "check\t", "apply\t"}},
		{name: "wireguard subcommands", words: []string{"wireguard", ""}, want: []string{"apply\t", "show\t", "shields-up\t"}},
		{name: "wireguard shields profile", words: []string{"wireguard", "shields-up", "w"}, want: []string{"work\tdisabled"}},
		{name: "wireguard shields state", words: []string{"wireguard", "shields-up", "work", ""}, want: []string{"off\t", "on\t"}},
		{name: "long flag", words: []string{"routes", "bind", "--pro"}, want: []string{"--profile\t"}},
		{name: "profile flag value", words: []string{"routes", "bind", "--profile", "w"}, want: []string{"work\tdisabled"}},
		{name: "profile operand", words: []string{"profiles", "show", "h"}, want: []string{"home\trunning"}},
		{name: "boolean flag value", words: []string{"routes", "set", "--accept-all="}, want: []string{"false\t", "true\t"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"completion", "__complete", "--"}
			args = append(args, test.words...)
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), args,
				testDependencies(client, &stdout, &stderr, nil))
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			for _, want := range test.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("completion output does not contain %q:\n%s", want, stdout.String())
				}
			}
			if !strings.HasSuffix(stdout.String(), ":4\n") {
				t.Errorf("completion output does not disable file completion:\n%s", stdout.String())
			}
		})
	}
}

func TestCompletionDelegatesToSelectedTailscaleProfile(t *testing.T) {
	client := &fakeManagementClient{profile: controlapi.Profile{
		Name: "work", LocalAPISocket: "/tmp/work.sock",
	}}
	var gotArgs []string
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"completion", "__complete", "--", "ts", "--profile", "work", "st"},
		testDependencies(client, &stdout, &stderr, func(_ context.Context, args []string) error {
			gotArgs = slices.Clone(args)
			return nil
		}))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	want := []string{"--socket=/tmp/work.sock", "completion", "__complete", "--", "st"}
	if !slices.Equal(gotArgs, want) {
		t.Fatalf("upstream completion args = %q, want %q", gotArgs, want)
	}
}

func TestCompletionDoesNotDelegateWhileDaemonDown(t *testing.T) {
	client := &fakeManagementClient{profile: controlapi.Profile{
		Name: "work", RuntimeState: "down",
	}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"completion", "__complete", "--", "ts", "--profile", "work", "st"},
		testDependencies(client, &stdout, &stderr, func(context.Context, []string) error {
			t.Fatal("upstream completion unexpectedly called")
			return nil
		}))
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "status\t") {
		t.Fatalf("fallback completion = %q", stdout.String())
	}
}

func TestVersion(t *testing.T) {
	client := &fakeManagementClient{serverVersion: tailmixversion.Meta{
		Short:            "daemon-version",
		Long:             "daemon-long-version",
		TailscaleVersion: "tailscale-version",
	}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"version"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	want := "tailmix test-version\n\n" +
		"tailmixd daemon-version\n" +
		"  long version: daemon-long-version\n" +
		"  tailscale: tailscale-version\n"
	if got := stdout.String(); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestVersionReportsUnavailableDaemon(t *testing.T) {
	client := &fakeManagementClient{versionErr: errors.New("unavailable")}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"version"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "tailmix test-version\n\ntailmixd unavailable\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
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

func TestStatusShowsActiveProfilesAndAcceptedPolicy(t *testing.T) {
	prefix := netip.MustParsePrefix("10.20.0.0/16")
	client := &fakeManagementClient{
		status: controlapi.Status{
			State: "up",
			Profiles: []controlapi.Profile{{
				ID: "work-id", Name: "work", Enabled: true, RuntimeState: "running",
				MagicDNSSuffix: "corp.example", PeerCount: 3,
			}},
			IPRoutes: controlapi.IPRoutes{Bindings: []controlapi.IPRouteBinding{{
				Prefix: prefix, ProfileID: "work-id", ProfileName: "work",
				State: "installed", CoveringRoute: prefix,
			}}},
			ExitNodes: controlapi.ExitNodes{Selected: &controlapi.SelectedExitNode{
				ProfileID: "work-id", ProfileName: "work", NodeID: "gateway-id",
				DNSName: "gateway.corp.example", Online: true, State: "installed",
			}},
			DNSRoutes: controlapi.DNSRoutes{Automatic: []controlapi.DNSRouteBinding{{
				Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
				Source: "magicdns", State: "installed",
			}}},
			SearchDomains: controlapi.SearchDomains{
				Desired: []string{"corp.example"},
				Installed: []controlapi.InstalledSearchDomain{{
					Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
				}},
			},
		},
	}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"status"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"STATE\tup", "PROFILE", "work", "running", "corp.example",
		"IP ROUTES", prefix.String(),
		"EXIT NODE", "gateway.corp.example",
		"DNS ROUTES", "magicdns",
		"DNS SEARCH", "ORDER",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("status does not contain %q:\n%s", want, stdout.String())
		}
	}
}

func TestStatusJSONIncludesAcceptedPolicy(t *testing.T) {
	client := &fakeManagementClient{
		status: controlapi.Status{
			State:    "down",
			Profiles: []controlapi.Profile{{ID: "work-id", Name: "work"}},
			DNSRoutes: controlapi.DNSRoutes{Automatic: []controlapi.DNSRouteBinding{{
				Domain: "corp.example", ProfileID: "work-id", ProfileName: "work",
				State: "installed",
			}}},
		},
	}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"status", "--json"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var got controlapi.Status
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != "down" || len(got.Profiles) != 1 || got.Profiles[0].Name != "work" {
		t.Fatalf("status JSON = %+v", got)
	}
	if len(got.DNSRoutes.Automatic) != 1 || got.DNSRoutes.Automatic[0].Domain != "corp.example" {
		t.Fatalf("status JSON DNS routes = %+v", got.DNSRoutes)
	}
}

func TestStatusOmitsEmptyPolicySections(t *testing.T) {
	client := &fakeManagementClient{status: controlapi.Status{
		State:    "down",
		Profiles: []controlapi.Profile{{ID: "work-id", Name: "work"}},
	}}
	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"status"},
		testDependencies(client, &stdout, &stderr, nil))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, unwanted := range []string{"IP ROUTES", "EXIT NODE", "DNS ROUTES", "DNS SEARCH", "(none)"} {
		if strings.Contains(stdout.String(), unwanted) {
			t.Errorf("empty status unexpectedly contains %q:\n%s", unwanted, stdout.String())
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

func TestExitNodeSetAndClearRequests(t *testing.T) {
	client := &fakeManagementClient{}
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "set", "--profile", "work", "gateway"},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 {
		t.Fatalf("set exit code = %d", code)
	}
	if client.exitSet.ProfileName != "work" || client.exitSet.Peer != "gateway" {
		t.Fatalf("set request = %+v", client.exitSet)
	}

	code = runWithDependencies(context.Background(),
		[]string{"exit-node", "clear"},
		testDependencies(client, io.Discard, io.Discard, nil))
	if code != 0 || !client.exitCleared {
		t.Fatalf("clear exit code = %d, cleared = %v", code, client.exitCleared)
	}
}

func TestExitNodeListShowsSelectedAndAvailableNodes(t *testing.T) {
	nodeIP := netip.MustParseAddr("100.64.0.20")
	client := &fakeManagementClient{exitNodes: controlapi.ExitNodes{
		Selected: &controlapi.SelectedExitNode{
			ProfileID: "work-id", ProfileName: "work", NodeID: "node-id",
			DNSName: "gateway.tailnet.ts.net", PeerIP: nodeIP, Online: true, State: "installed",
		},
		Available: []controlapi.AvailableExitNode{{
			ProfileID: "work-id", ProfileName: "work", NodeID: "node-id",
			DNSName: "gateway.tailnet.ts.net", IPs: []netip.Addr{nodeIP}, Online: true,
		}},
	}}
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "list"},
		testDependencies(client, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("list exit code = %d", code)
	}
	for _, want := range []string{"PROFILE", "gateway.tailnet.ts.net", nodeIP.String(), "yes", "✓"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("exit-node list does not contain %q:\n%s", want, stdout.String())
		}
	}
}

func TestExitNodeListUsesTailscaleLocationFiltering(t *testing.T) {
	client := &fakeManagementClient{exitNodes: cliLocationExitNodes()}
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "list"},
		testDependencies(client, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("list exit code = %d", code)
	}
	output := stdout.String()
	for _, want := range []string{
		"COUNTRY", "CITY", "Canada", "Any", "squamish-high", "squamish-selected",
		"vancouver-high", "Germany", "legacy",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("exit-node list does not contain %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "vancouver-hidden") {
		t.Fatalf("lower-priority city peer was not hidden:\n%s", output)
	}
}

func TestExitNodeListCountryFilterShowsCompleteCountry(t *testing.T) {
	client := &fakeManagementClient{exitNodes: cliLocationExitNodes()}
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "list", "--filter", "cAnAdA"},
		testDependencies(client, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("filtered list exit code = %d", code)
	}
	output := stdout.String()
	for _, want := range []string{"squamish-high", "squamish-selected", "vancouver-high", "vancouver-hidden"} {
		if !strings.Contains(output, want) {
			t.Fatalf("filtered list does not contain %q:\n%s", want, output)
		}
	}
	for _, hidden := range []string{"Any", "berlin", "legacy"} {
		if strings.Contains(output, hidden) {
			t.Fatalf("filtered list unexpectedly contains %q:\n%s", hidden, output)
		}
	}
}

func TestExitNodeListCountryFilterPreservesJSONSchema(t *testing.T) {
	client := &fakeManagementClient{exitNodes: cliLocationExitNodes()}
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "list", "--filter=Canada", "--json"},
		testDependencies(client, &stdout, io.Discard, nil))
	if code != 0 {
		t.Fatalf("filtered JSON exit code = %d", code)
	}
	var got controlapi.ExitNodes
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Available) != 4 || got.Selected == nil || got.Selected.NodeID != "squamish-selected" {
		t.Fatalf("filtered JSON = %+v", got)
	}
}

func TestExitNodeListRejectsUnknownCountryFilter(t *testing.T) {
	client := &fakeManagementClient{exitNodes: cliLocationExitNodes()}
	var stderr bytes.Buffer
	code := runWithDependencies(context.Background(),
		[]string{"exit-node", "list", "--filter", "France"},
		testDependencies(client, io.Discard, &stderr, nil))
	if code != 1 || !strings.Contains(stderr.String(), `no exit nodes found for "France"`) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func cliLocationExitNodes() controlapi.ExitNodes {
	location := func(country, countryCode, city, cityCode string, priority int) *controlapi.ExitNodeLocation {
		return &controlapi.ExitNodeLocation{
			Country: country, CountryCode: countryCode, City: city, CityCode: cityCode, Priority: priority,
		}
	}
	node := func(id string, loc *controlapi.ExitNodeLocation) controlapi.AvailableExitNode {
		return controlapi.AvailableExitNode{
			ProfileID: "p1", ProfileName: "work", NodeID: id,
			DNSName: id + ".example.ts.net", Online: true, Location: loc,
		}
	}
	return controlapi.ExitNodes{
		Available: []controlapi.AvailableExitNode{
			node("legacy", nil),
			node("squamish-high", location("Canada", "CA", "Squamish", "YSE", 100)),
			node("squamish-selected", location("Canada", "CA", "Squamish", "YSE", 10)),
			node("vancouver-high", location("Canada", "CA", "Vancouver", "YVR", 50)),
			node("vancouver-hidden", location("Canada", "CA", "Vancouver", "YVR", 1)),
			node("berlin", location("Germany", "DE", "Berlin", "BER", 5)),
		},
		Selected: &controlapi.SelectedExitNode{
			ProfileID: "p1", ProfileName: "work", NodeID: "squamish-selected",
			DNSName: "squamish-selected.example.ts.net", Online: true, State: "installed",
		},
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
