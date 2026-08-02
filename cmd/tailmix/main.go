package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/exitnodeview"
	"github.com/maisem/tailmix/profilesocket"
	tailmixversion "github.com/maisem/tailmix/version"
	"tailscale.com/cmd/tailscale/cli"
	"tailscale.com/util/dnsname"
)

type cliRunner func(context.Context, []string) error

type managementClient interface {
	Version(context.Context) (tailmixversion.Meta, error)
	Status(context.Context) (controlapi.Status, error)
	UpdateStatus(context.Context) (controlapi.UpdateStatus, error)
	UpdateAction(context.Context, string) (controlapi.UpdateStatus, error)
	Profiles(context.Context, bool) (controlapi.Profiles, error)
	Profile(context.Context, string) (controlapi.Profile, error)
	AddProfile(context.Context, controlapi.AddProfileRequest) (controlapi.Profile, error)
	PatchProfile(context.Context, string, controlapi.PatchProfileRequest) (controlapi.Profile, error)
	ProfileAction(context.Context, string, string) (controlapi.Profile, error)
	RemoveProfile(context.Context, string, bool) (controlapi.Profile, error)
	IPRoutes(context.Context, bool) (controlapi.IPRoutes, error)
	PatchIPRoutes(context.Context, controlapi.PatchIPRoutesRequest) (controlapi.IPRoutes, error)
	ExitNodes(context.Context) (controlapi.ExitNodes, error)
	SetExitNode(context.Context, controlapi.SetExitNodeRequest) (controlapi.ExitNodes, error)
	ClearExitNode(context.Context) (controlapi.ExitNodes, error)
	DNSRoutes(context.Context, bool) (controlapi.DNSRoutes, error)
	PatchDNSRoutes(context.Context, controlapi.PatchDNSRoutesRequest) (controlapi.DNSRoutes, error)
	SearchDomains(context.Context) (controlapi.SearchDomains, error)
	ReplaceSearchDomains(context.Context, []string) (controlapi.SearchDomains, error)
	PatchSearchDomains(context.Context, controlapi.PatchSearchDomainsRequest) (controlapi.SearchDomains, error)
	ClearSearchDomains(context.Context) (controlapi.SearchDomains, error)
}

type usageError struct {
	message string
}

func (e usageError) Error() string { return e.message }

type dependencies struct {
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	runCLI    cliRunner
	newClient func(string) managementClient
	version   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runWithIO(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, cli.RunWithContext))
}

func runWithIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runCLI cliRunner) int {
	return runWithDependencies(ctx, args, dependencies{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		runCLI: runCLI,
		newClient: func(socketDir string) managementClient {
			return controlapi.NewClient(socketDir)
		},
		version: tailmixversion.String(),
	})
}

func runWithDependencies(ctx context.Context, args []string, deps dependencies) int {
	socketDir, args, err := globalOptions(args)
	if err != nil {
		fmt.Fprintln(deps.stderr, err)
		fmt.Fprintln(deps.stderr, `Run "tailmix help" for usage.`)
		return 2
	}
	if len(args) == 0 {
		fmt.Fprint(deps.stderr, rootHelp)
		return 2
	}
	if isHelp(args[0]) {
		fmt.Fprint(deps.stdout, rootHelp)
		return 0
	}

	client := deps.newClient(socketDir)
	switch args[0] {
	case "status":
		err = runStatus(ctx, client, args[1:], deps)
	case "update":
		err = runUpdate(ctx, client, args[1:], deps)
	case "profiles":
		err = runProfiles(ctx, client, args[1:], deps)
	case "routes":
		err = runRoutes(ctx, client, args[1:], deps)
	case "exit-node":
		err = runExitNode(ctx, client, args[1:], deps)
	case "dns":
		err = runDNS(ctx, client, args[1:], deps)
	case "tailscale", "ts":
		err = runTailscale(ctx, client, socketDir, args[1:], deps)
	case "completion":
		err = runCompletion(ctx, socketDir, args[1:], deps)
	case "version":
		err = runVersion(ctx, client, args[1:], deps)
	default:
		if len(args) > 1 {
			err = usageError{fmt.Sprintf("ambiguous legacy syntax; use %q", "tailmix ts --profile "+args[0]+" "+strings.Join(args[1:], " "))}
		} else {
			err = usageError{fmt.Sprintf("unknown command %q", args[0])}
		}
	}
	if err == nil {
		return 0
	}
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(deps.stderr, usage.message)
		fmt.Fprintln(deps.stderr, `Run "tailmix help" for usage.`)
		return 2
	}
	fmt.Fprintln(deps.stderr, err)
	return 1
}

func runUpdate(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, updateHelp)
		return nil
	}
	action := args[0]
	if action != "status" && action != "enable" && action != "disable" && action != "check" && action != "apply" {
		return usageError{fmt.Sprintf("unknown update command %q", action)}
	}
	rest := args[1:]
	jsonOutput, err := takeBool(&rest, "--json")
	if err != nil {
		return err
	}
	if err := noOperands(rest); err != nil {
		return err
	}
	var result controlapi.UpdateStatus
	if action == "status" {
		result, err = client.UpdateStatus(ctx)
	} else {
		result, err = client.UpdateAction(ctx, action)
	}
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(deps.stdout, result)
	}
	writeUpdateStatus(deps.stdout, result)
	return nil
}

func writeUpdateStatus(w io.Writer, status controlapi.UpdateStatus) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "ENABLED\t%s\nCURRENT VERSION\t%s\nSTATE\t%s\n", yesNo(status.Enabled), status.CurrentVersion, status.State)
	if status.AvailableVersion != "" {
		fmt.Fprintf(table, "AVAILABLE VERSION\t%s\n", status.AvailableVersion)
	}
	if status.LastChecked != "" {
		fmt.Fprintf(table, "LAST CHECKED\t%s\n", status.LastChecked)
	}
	if status.LastError != "" {
		fmt.Fprintf(table, "LAST ERROR\t%s\n", status.LastError)
	}
	_ = table.Flush()
}

func runVersion(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) > 0 && isHelp(args[0]) {
		fmt.Fprint(deps.stdout, versionHelp)
		return nil
	}
	if err := noOperands(args); err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, deps.version)
	fmt.Fprintln(deps.stdout)
	serverVersion, err := client.Version(ctx)
	if err != nil {
		fmt.Fprintln(deps.stdout, "tailmixd unavailable")
		return nil
	}
	fmt.Fprintln(deps.stdout, serverVersion.Format("tailmixd"))
	return nil
}

func runStatus(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) > 0 && isHelp(args[0]) {
		fmt.Fprint(deps.stdout, statusHelp)
		return nil
	}
	jsonOutput, err := takeBool(&args, "--json")
	if err != nil {
		return err
	}
	if err := noOperands(args); err != nil {
		return err
	}
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(deps.stdout, status)
	}
	writeStatus(deps.stdout, status)
	return nil
}

func runProfiles(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, profilesHelp)
		return nil
	}
	switch args[0] {
	case "list":
		rest := args[1:]
		all, err := takeBool(&rest, "--all")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err := client.Profiles(ctx, all)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		writeProfiles(deps.stdout, result.Profiles)
		return nil
	case "show":
		rest := args[1:]
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		name, err := oneOperand(rest, "profile name")
		if err != nil {
			return err
		}
		result, err := client.Profile(ctx, name)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		writeProfile(deps.stdout, result)
		return nil
	case "add":
		return runProfileAdd(ctx, client, args[1:], deps)
	case "rename":
		if len(args) != 3 {
			return usageError{"usage: tailmix profiles rename <profile> <new-profile>"}
		}
		newName := args[2]
		result, err := client.PatchProfile(ctx, args[1], controlapi.PatchProfileRequest{Name: &newName})
		if err != nil {
			return err
		}
		fmt.Fprintf(deps.stdout, "Profile %q renamed to %q.\n", args[1], result.Name)
		return nil
	case "set":
		return runProfileSet(ctx, client, args[1:], deps)
	case "enable", "disable", "restart":
		rest := args[1:]
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		name, err := oneOperand(rest, "profile name")
		if err != nil {
			return err
		}
		result, err := client.ProfileAction(ctx, name, args[0])
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		fmt.Fprintf(deps.stdout, "Profile %q is %s.\n", result.Name, result.RuntimeState)
		return nil
	case "remove":
		rest := args[1:]
		purge, err := takeBool(&rest, "--purge")
		if err != nil {
			return err
		}
		yes, err := takeBool(&rest, "--yes")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		name, err := oneOperand(rest, "profile name")
		if err != nil {
			return err
		}
		if yes && !purge {
			return usageError{"--yes requires --purge"}
		}
		if purge && !yes {
			confirmed, err := confirmPurge(deps.stdin, deps.stderr, name)
			if err != nil {
				return err
			}
			if !confirmed {
				fmt.Fprintln(deps.stderr, "Purge canceled.")
				return nil
			}
		}
		result, err := client.RemoveProfile(ctx, name, purge)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		if purge {
			fmt.Fprintf(deps.stdout, "Profile %q purged.\n", name)
		} else {
			fmt.Fprintf(deps.stdout, "Profile %q removed; identity and bindings retained.\n", name)
		}
		return nil
	default:
		return usageError{fmt.Sprintf("unknown profiles command %q", args[0])}
	}
}

func runProfileAdd(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	rest := append([]string(nil), args...)
	hostname, hostnameSet, err := takeString(&rest, "--hostname")
	if err != nil {
		return err
	}
	stateDir, _, err := takeString(&rest, "--state-dir")
	if err != nil {
		return err
	}
	authEnv, authEnvSet, err := takeString(&rest, "--auth-key-env")
	if err != nil {
		return err
	}
	authFile, authFileSet, err := takeString(&rest, "--auth-key-file")
	if err != nil {
		return err
	}
	disabled, err := takeBool(&rest, "--disabled")
	if err != nil {
		return err
	}
	jsonOutput, err := takeBool(&rest, "--json")
	if err != nil {
		return err
	}
	name, err := oneOperand(rest, "profile name")
	if err != nil {
		return err
	}
	if authEnvSet && authFileSet {
		return usageError{"--auth-key-env and --auth-key-file are mutually exclusive"}
	}
	authKey := ""
	if authEnvSet {
		authKey = os.Getenv(authEnv)
		if authKey == "" {
			return fmt.Errorf("auth key environment variable %s is empty", authEnv)
		}
	}
	if authFileSet {
		authKey, err = readAuthKey(deps.stdin, authFile)
		if err != nil {
			return err
		}
	}
	request := controlapi.AddProfileRequest{
		Name:     name,
		StateDir: stateDir,
		AuthKey:  authKey,
		Disabled: disabled,
	}
	if hostnameSet {
		request.Hostname = hostname
	}
	result, err := client.AddProfile(ctx, request)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(deps.stdout, result)
	}
	if result.RuntimeState == "needs-login" && result.AuthURL != "" {
		fmt.Fprintf(deps.stdout, "Profile %q added; login required.\nRun: tailmix ts --profile %s up\n", result.Name, result.Name)
		return nil
	}
	fmt.Fprintf(deps.stdout, "Profile %q added (%s).\n", result.Name, result.RuntimeState)
	return nil
}

func runProfileSet(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	rest := append([]string(nil), args...)
	hostname, hostnameSet, err := takeString(&rest, "--hostname")
	if err != nil {
		return err
	}
	jsonOutput, err := takeBool(&rest, "--json")
	if err != nil {
		return err
	}
	name, err := oneOperand(rest, "profile name")
	if err != nil {
		return err
	}
	if !hostnameSet {
		return usageError{"profiles set requires --hostname"}
	}
	request := controlapi.PatchProfileRequest{}
	if hostnameSet {
		request.Hostname = &hostname
	}
	result, err := client.PatchProfile(ctx, name, request)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(deps.stdout, result)
	}
	fmt.Fprintf(deps.stdout, "Profile %q updated (%s).\n", result.Name, result.RuntimeState)
	return nil
}

func runRoutes(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, routesHelp)
		return nil
	}
	switch args[0] {
	case "list":
		rest := args[1:]
		available, err := takeBool(&rest, "--available")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err := client.IPRoutes(ctx, available)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		writeIPRoutes(deps.stdout, result, available)
		return nil
	case "bind":
		rest := args[1:]
		profileName, set, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		replace, err := takeBool(&rest, "--replace")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if !set {
			return usageError{"routes bind requires --profile"}
		}
		prefixes, err := parsePrefixes(rest)
		if err != nil {
			return err
		}
		request := controlapi.PatchIPRoutesRequest{Replace: replace}
		for _, prefix := range prefixes {
			request.Bind = append(request.Bind, controlapi.IPRouteMutation{Prefix: prefix, ProfileName: profileName})
		}
		result, err := client.PatchIPRoutes(ctx, request)
		if err != nil {
			return err
		}
		return writeIPMutationResult(deps.stdout, result, jsonOutput)
	case "unbind":
		rest := args[1:]
		profileName, _, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		prefixes, err := parsePrefixes(rest)
		if err != nil {
			return err
		}
		request := controlapi.PatchIPRoutesRequest{}
		for _, prefix := range prefixes {
			request.Unbind = append(request.Unbind, controlapi.IPRouteUnbind{Prefix: prefix, ProfileName: profileName})
		}
		result, err := client.PatchIPRoutes(ctx, request)
		if err != nil {
			return err
		}
		return writeIPMutationResult(deps.stdout, result, jsonOutput)
	case "set":
		rest := args[1:]
		profileName, set, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		acceptAll, acceptAllSet, err := takeBoolValue(&rest, "--accept-all")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if !set || !acceptAllSet || len(rest) != 0 {
			return usageError{"usage: tailmix routes set --profile <profile> --accept-all=<true|false> [--json]"}
		}
		result, err := client.PatchIPRoutes(ctx, controlapi.PatchIPRoutesRequest{AcceptAll: map[string]bool{profileName: acceptAll}})
		if err != nil {
			return err
		}
		return writeIPMutationResult(deps.stdout, result, jsonOutput)
	default:
		return usageError{fmt.Sprintf("unknown routes command %q", args[0])}
	}
}

func runExitNode(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, exitNodeHelp)
		return nil
	}
	rest := args[1:]
	jsonOutput, err := takeBool(&rest, "--json")
	if err != nil {
		return err
	}
	filterCountry, filterSet, err := takeString(&rest, "--filter")
	if err != nil {
		return err
	}
	filterCountry = strings.TrimSpace(filterCountry)
	if filterSet && filterCountry == "" {
		return usageError{"--filter cannot be empty"}
	}
	if filterSet && args[0] != "list" {
		return usageError{"--filter is only supported by exit-node list"}
	}
	var result controlapi.ExitNodes
	switch args[0] {
	case "list":
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err = client.ExitNodes(ctx)
	case "set":
		profileName, set, parseErr := takeProfile(&rest)
		if parseErr != nil {
			return parseErr
		}
		if !set || strings.TrimSpace(profileName) == "" {
			return usageError{"exit-node set requires --profile"}
		}
		peer, parseErr := oneOperand(rest, "exit node peer")
		if parseErr != nil {
			return parseErr
		}
		result, err = client.SetExitNode(ctx, controlapi.SetExitNodeRequest{
			ProfileName: profileName,
			Peer:        peer,
		})
	case "clear":
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err = client.ClearExitNode(ctx)
	default:
		return usageError{fmt.Sprintf("unknown exit-node command %q", args[0])}
	}
	if err != nil {
		return err
	}
	if filterSet {
		result = exitnodeview.FilterCountry(result, filterCountry)
		if len(result.Available) == 0 && result.Selected == nil {
			return fmt.Errorf("no exit nodes found for %q", filterCountry)
		}
	}
	if jsonOutput {
		return writeJSON(deps.stdout, result)
	}
	writeExitNodes(deps.stdout, result, filterCountry)
	return nil
}

func runDNS(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, dnsHelp)
		return nil
	}
	switch args[0] {
	case "routes":
		return runDNSRoutes(ctx, client, args[1:], deps)
	case "search":
		return runDNSSearch(ctx, client, args[1:], deps)
	default:
		return usageError{fmt.Sprintf("unknown dns command %q", args[0])}
	}
}

func runDNSRoutes(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, dnsRoutesHelp)
		return nil
	}
	switch args[0] {
	case "list":
		rest := args[1:]
		available, err := takeBool(&rest, "--available")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err := client.DNSRoutes(ctx, available)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(deps.stdout, result)
		}
		writeDNSRoutes(deps.stdout, result, available)
		return nil
	case "bind":
		rest := args[1:]
		profileName, set, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		replace, err := takeBool(&rest, "--replace")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if !set {
			return usageError{"dns routes bind requires --profile"}
		}
		domains, err := parseDomains(rest, true)
		if err != nil {
			return err
		}
		request := controlapi.PatchDNSRoutesRequest{Replace: replace}
		for _, domain := range domains {
			request.Bind = append(request.Bind, controlapi.DNSRouteMutation{Domain: domain, ProfileName: profileName})
		}
		result, err := client.PatchDNSRoutes(ctx, request)
		if err != nil {
			return err
		}
		return writeDNSMutationResult(deps.stdout, result, jsonOutput)
	case "unbind":
		rest := args[1:]
		profileName, _, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		domains, err := parseDomains(rest, true)
		if err != nil {
			return err
		}
		request := controlapi.PatchDNSRoutesRequest{}
		for _, domain := range domains {
			request.Unbind = append(request.Unbind, controlapi.DNSRouteUnbind{Domain: domain, ProfileName: profileName})
		}
		result, err := client.PatchDNSRoutes(ctx, request)
		if err != nil {
			return err
		}
		return writeDNSMutationResult(deps.stdout, result, jsonOutput)
	case "set":
		rest := args[1:]
		profileName, set, err := takeProfile(&rest)
		if err != nil {
			return err
		}
		acceptAll, acceptAllSet, err := takeBoolValue(&rest, "--accept-all")
		if err != nil {
			return err
		}
		jsonOutput, err := takeBool(&rest, "--json")
		if err != nil {
			return err
		}
		if !set || !acceptAllSet || len(rest) != 0 {
			return usageError{"usage: tailmix dns routes set --profile <profile> --accept-all=<true|false> [--json]"}
		}
		result, err := client.PatchDNSRoutes(ctx, controlapi.PatchDNSRoutesRequest{AcceptAll: map[string]bool{profileName: acceptAll}})
		if err != nil {
			return err
		}
		return writeDNSMutationResult(deps.stdout, result, jsonOutput)
	default:
		return usageError{fmt.Sprintf("unknown dns routes command %q", args[0])}
	}
}

func runDNSSearch(ctx context.Context, client managementClient, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, dnsSearchHelp)
		return nil
	}
	rest := args[1:]
	jsonOutput, err := takeBool(&rest, "--json")
	if err != nil {
		return err
	}
	var result controlapi.SearchDomains
	switch args[0] {
	case "list":
		if err := noOperands(rest); err != nil {
			return err
		}
		result, err = client.SearchDomains(ctx)
	case "set":
		var domains []string
		domains, err = parseDomains(rest, false)
		if err == nil {
			result, err = client.ReplaceSearchDomains(ctx, domains)
		}
	case "add":
		var domains []string
		domains, err = parseDomains(rest, false)
		if err == nil {
			result, err = client.PatchSearchDomains(ctx, controlapi.PatchSearchDomainsRequest{Add: domains})
		}
	case "remove":
		var domains []string
		domains, err = parseDomains(rest, false)
		if err == nil {
			result, err = client.PatchSearchDomains(ctx, controlapi.PatchSearchDomainsRequest{Remove: domains})
		}
	case "clear":
		if err = noOperands(rest); err == nil {
			result, err = client.ClearSearchDomains(ctx)
		}
	default:
		return usageError{fmt.Sprintf("unknown dns search command %q", args[0])}
	}
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(deps.stdout, result)
	}
	writeSearchDomains(deps.stdout, result)
	return nil
}

func runTailscale(ctx context.Context, client managementClient, socketDir string, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, tailscaleHelp)
		return nil
	}
	profileName, rest, set, err := takeLeadingProfile(args)
	if err != nil {
		return err
	}
	if !set || profileName == "" {
		return usageError{"tailscale delegation requires --profile <profile>"}
	}
	if len(rest) == 0 {
		return usageError{"a Tailscale subcommand is required"}
	}
	for _, arg := range rest {
		if arg == "--socket" || arg == "-socket" || strings.HasPrefix(arg, "--socket=") || strings.HasPrefix(arg, "-socket=") {
			return usageError{"the tailscale --socket flag is managed by tailmix"}
		}
	}
	if len(rest) == 1 {
		switch rest[0] {
		case "help":
			rest = []string{"--help"}
		case "-V", "--version":
			rest = []string{"version"}
		}
	}
	selected, err := client.Profile(ctx, profileName)
	if err != nil {
		return err
	}
	socketPath, err := profileLocalAPISocket(socketDir, selected)
	if err != nil {
		return err
	}
	cliArgs := append([]string{"--socket=" + socketPath}, rest...)
	oldStdout, oldStderr := cli.Stdout, cli.Stderr
	cli.Stdout, cli.Stderr = deps.stdout, deps.stderr
	defer func() {
		cli.Stdout, cli.Stderr = oldStdout, oldStderr
	}()
	return deps.runCLI(ctx, cliArgs)
}

func profileLocalAPISocket(socketDir string, selected controlapi.Profile) (string, error) {
	if selected.LocalAPISocket != "" {
		return selected.LocalAPISocket, nil
	}
	return profilesocket.Path(socketDir, selected.ID)
}

func globalOptions(args []string) (string, []string, error) {
	socketDir := profilesocket.DefaultDir()
	value, rest, set, err := takeLeadingString(args, "--socket-dir")
	if err != nil {
		return "", nil, err
	}
	if set {
		socketDir = strings.TrimSpace(value)
		if socketDir == "" {
			return "", nil, usageError{"--socket-dir cannot be empty"}
		}
	}
	return socketDir, rest, nil
}

func takeLeadingString(args []string, name string) (value string, rest []string, found bool, err error) {
	return takeLeadingStringAliases(args, name)
}

func takeLeadingProfile(args []string) (value string, rest []string, found bool, err error) {
	return takeLeadingStringAliases(args, "--profile", "-p")
}

func takeLeadingStringAliases(args []string, names ...string) (value string, rest []string, found bool, err error) {
	rest = append([]string(nil), args...)
	if len(rest) == 0 {
		return "", rest, false, nil
	}
	for _, name := range names {
		if rest[0] == name {
			if len(rest) < 2 {
				return "", nil, false, usageError{name + " requires a value"}
			}
			return rest[1], rest[2:], true, nil
		}
		if strings.HasPrefix(rest[0], name+"=") {
			return strings.TrimPrefix(rest[0], name+"="), rest[1:], true, nil
		}
	}
	return "", rest, false, nil
}

func takeString(args *[]string, name string) (string, bool, error) {
	return takeStringAliases(args, name)
}

func takeProfile(args *[]string) (string, bool, error) {
	return takeStringAliases(args, "--profile", "-p")
}

func takeStringAliases(args *[]string, names ...string) (string, bool, error) {
	var value string
	found := false
	out := (*args)[:0]
	for i := 0; i < len(*args); i++ {
		arg := (*args)[i]
		matchedName := ""
		hasInlineValue := false
		for _, name := range names {
			if arg == name {
				matchedName = name
				break
			}
			if strings.HasPrefix(arg, name+"=") {
				matchedName = name
				hasInlineValue = true
				break
			}
		}
		if matchedName == "" {
			out = append(out, arg)
			continue
		}
		if found {
			return "", false, usageError{names[0] + " may be specified only once"}
		}
		if hasInlineValue {
			value = strings.TrimPrefix(arg, matchedName+"=")
		} else {
			if i+1 >= len(*args) {
				return "", false, usageError{matchedName + " requires a value"}
			}
			value = (*args)[i+1]
			i++
		}
		found = true
	}
	*args = out
	return value, found, nil
}

func takeBool(args *[]string, name string) (bool, error) {
	found := false
	out := (*args)[:0]
	for _, arg := range *args {
		if arg == name {
			if found {
				return false, usageError{name + " may be specified only once"}
			}
			found = true
			continue
		}
		if strings.HasPrefix(arg, name+"=") {
			return false, usageError{name + " does not take a value"}
		}
		out = append(out, arg)
	}
	*args = out
	return found, nil
}

func takeBoolValue(args *[]string, name string) (bool, bool, error) {
	raw, found, err := takeString(args, name)
	if err != nil || !found {
		return false, found, err
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false, usageError{fmt.Sprintf("%s must be true or false", name)}
	}
	return value, true, nil
}

func noOperands(args []string) error {
	if len(args) != 0 {
		return usageError{fmt.Sprintf("unexpected arguments: %s", strings.Join(args, " "))}
	}
	return nil
}

func oneOperand(args []string, description string) (string, error) {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return "", usageError{"exactly one " + description + " is required"}
	}
	return args[0], nil
}

func parsePrefixes(args []string) ([]netip.Prefix, error) {
	if len(args) == 0 {
		return nil, usageError{"at least one IP prefix is required"}
	}
	out := make([]netip.Prefix, 0, len(args))
	seen := map[netip.Prefix]bool{}
	for _, raw := range args {
		if strings.HasPrefix(raw, "-") {
			return nil, usageError{fmt.Sprintf("unknown option %q", raw)}
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, usageError{fmt.Sprintf("invalid IP prefix %q: %v", raw, err)}
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, usageError{fmt.Sprintf("default route %q must use exit-node policy", raw)}
		}
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out, nil
}

func parseDomains(args []string, allowRoot bool) ([]string, error) {
	if len(args) == 0 {
		return nil, usageError{"at least one DNS domain is required"}
	}
	out := make([]string, 0, len(args))
	seen := map[string]bool{}
	for _, raw := range args {
		if strings.HasPrefix(raw, "-") {
			return nil, usageError{fmt.Sprintf("unknown option %q", raw)}
		}
		domain, parseErr := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(raw)))
		if parseErr != nil || domain == dnsname.FQDN(".") && !allowRoot || strings.TrimSpace(raw) == "" {
			return nil, usageError{fmt.Sprintf("invalid DNS domain %q", raw)}
		}
		normalized := domain.WithoutTrailingDot()
		if domain == dnsname.FQDN(".") {
			normalized = "."
		}
		if !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out, nil
}

func readAuthKey(stdin io.Reader, path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(stdin, 64<<10))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("read auth key: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("auth key is empty")
	}
	return key, nil
}

func confirmPurge(stdin io.Reader, stderr io.Writer, profileName string) (bool, error) {
	fmt.Fprintf(stderr, "Permanently purge profile %q and its retained identity? [y/N] ", profileName)
	scanner := bufio.NewScanner(io.LimitReader(stdin, 4096))
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes", nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeProfiles(w io.Writer, profiles []controlapi.Profile) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PROFILE\tENABLED\tRUNTIME\tTAILNET\tPEERS\tERROR")
	for _, profile := range profiles {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%d\t%s\n",
			profile.Name, yesNo(profile.Enabled), profile.RuntimeState,
			profile.MagicDNSSuffix, profile.PeerCount, profile.LastError)
	}
	_ = table.Flush()
}

func writeStatus(w io.Writer, status controlapi.Status) {
	writeProfiles(w, status.Profiles)

	writeStatusSection(w, "IP ROUTES", statusHasIPRoutes(status.IPRoutes), func() {
		writeIPRoutes(w, status.IPRoutes, false)
	})
	writeStatusSection(w, "EXIT NODE", status.ExitNodes.Selected != nil || status.ExitNodes.ReconcileError != "", func() {
		writeExitNodes(w, status.ExitNodes, "")
	})
	writeStatusSection(w, "DNS ROUTES", statusHasDNSRoutes(status.DNSRoutes), func() {
		writeDNSRoutes(w, status.DNSRoutes, false)
	})
	writeStatusSection(w, "DNS SEARCH", statusHasSearchDomains(status.SearchDomains), func() {
		writeSearchDomains(w, status.SearchDomains)
	})
}

func writeStatusSection(w io.Writer, title string, present bool, write func()) {
	if !present {
		return
	}
	fmt.Fprintf(w, "\n%s\n", title)
	write()
}

func statusHasIPRoutes(routes controlapi.IPRoutes) bool {
	return len(routes.AcceptAllProfiles) > 0 || len(routes.Bindings) > 0 ||
		len(routes.Imported) > 0 || routes.ReconcileError != ""
}

func statusHasDNSRoutes(routes controlapi.DNSRoutes) bool {
	return len(routes.AcceptAllProfiles) > 0 || len(routes.Bindings) > 0 ||
		len(routes.Imported) > 0 || len(routes.Automatic) > 0 || routes.ReconcileError != ""
}

func statusHasSearchDomains(domains controlapi.SearchDomains) bool {
	return len(domains.Desired) > 0 || len(domains.Installed) > 0 ||
		len(domains.Waiting) > 0 || domains.ReconcileError != ""
}

func writeProfile(w io.Writer, profile controlapi.Profile) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	rows := [][2]string{
		{"Profile", profile.Name},
		{"ID", profile.ID},
		{"Enabled", yesNo(profile.Enabled)},
		{"Removed", yesNo(profile.Removed)},
		{"Runtime", profile.RuntimeState},
		{"Backend", profile.BackendState},
		{"State directory", profile.StateDir},
		{"Hostname", profile.Hostname},
		{"Tailnet", profile.MagicDNSSuffix},
		{"Self DNS", profile.SelfDNSName},
		{"Accept all routes", yesNo(profile.AcceptAllRoutes)},
		{"Accept all DNS routes", yesNo(profile.AcceptAllDNSRoutes)},
		{"LocalAPI socket", profile.LocalAPISocket},
		{"Error", profile.LastError},
	}
	for _, row := range rows {
		fmt.Fprintf(table, "%s:\t%s\n", row[0], row[1])
	}
	_ = table.Flush()
}

func writeIPRoutes(w io.Writer, routes controlapi.IPRoutes, available bool) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if available {
		fmt.Fprintln(table, "PREFIX\tPROFILE\tADVERTISED BY")
		for _, route := range routes.Available {
			fmt.Fprintf(table, "%s\t%s\t%s\n", route.Prefix, route.ProfileName, route.PrimaryRouter)
		}
		_ = table.Flush()
		return
	}
	fmt.Fprintln(table, "PREFIX\tPROFILE\tADVERTISED BY\tSTATE\tMATCHED ROUTE")
	shown := map[string]bool{}
	for _, route := range append(append([]controlapi.IPRouteBinding(nil), routes.Bindings...), routes.Imported...) {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			route.Prefix, route.ProfileName, route.PrimaryRouter,
			stateLabel(route.State, route.Reason), prefixLabel(route.CoveringRoute))
		shown[route.Prefix.String()+"\x00"+route.ProfileID+"\x00"+route.PrimaryRouter] = true
	}
	for _, route := range routes.Available {
		if shown[route.Prefix.String()+"\x00"+route.ProfileID+"\x00"+route.PrimaryRouter] {
			continue
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t\t\n", route.Prefix, route.ProfileName, route.PrimaryRouter)
	}
	for _, accepted := range routes.AcceptAllProfiles {
		fmt.Fprintf(table, "*\t%s\t\t%s\t\n",
			accepted.ProfileName, stateLabel(accepted.State, accepted.Reason))
	}
	if routes.ReconcileError != "" {
		fmt.Fprintf(table, "!\t\t\tfailed:%s\t\n", routes.ReconcileError)
	}
	_ = table.Flush()
}

func writeExitNodes(w io.Writer, nodes controlapi.ExitNodes, filterCountry string) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PROFILE\tEXIT NODE\tIPS\tCOUNTRY\tCITY\tONLINE\tSTATE")
	for _, item := range exitnodeview.Items(nodes, filterCountry) {
		node := item.Node
		state := ""
		if node.Selected {
			state = stateLabel(node.State, node.Reason)
		}
		ips := addressList(node.IPs)
		if ips == "" && node.PeerIP.IsValid() {
			ips = node.PeerIP.String()
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			node.ProfileName, exitNodeName(node.DNSName, node.NodeID),
			ips, locationLabel(item.Country), locationLabel(item.City),
			yesNo(node.Online), state)
	}
	if nodes.ReconcileError != "" {
		fmt.Fprintf(table, "!\t\t\t\t\t\tfailed:%s\n", nodes.ReconcileError)
	}
	_ = table.Flush()
}

func locationLabel(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func exitNodeName(dnsName, nodeID string) string {
	if dnsName != "" {
		return dnsName
	}
	return nodeID
}

func addressList(ips []netip.Addr) string {
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return strings.Join(values, ",")
}

func writeDNSRoutes(w io.Writer, routes controlapi.DNSRoutes, available bool) {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if available {
		fmt.Fprintln(table, "DOMAIN\tPROFILE\tSOURCE\tRESOLVERS")
		for _, route := range routes.Available {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", route.Domain, route.ProfileName, route.Source, resolverList(route.Resolvers))
		}
		_ = table.Flush()
		return
	}
	fmt.Fprintln(table, "DOMAIN\tPROFILE\tSOURCE\tSTATE\tRESOLVERS")
	all := append(append(append([]controlapi.DNSRouteBinding(nil), routes.Bindings...), routes.Imported...), routes.Automatic...)
	shown := map[string]bool{}
	for _, route := range all {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			route.Domain, route.ProfileName, route.Source,
			stateLabel(route.State, route.Reason), resolverList(route.Resolvers))
		shown[route.Domain+"\x00"+route.ProfileID+"\x00"+route.Source] = true
	}
	for _, route := range routes.Available {
		if shown[route.Domain+"\x00"+route.ProfileID+"\x00"+route.Source] {
			continue
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t\t%s\n",
			route.Domain, route.ProfileName, route.Source, resolverList(route.Resolvers))
	}
	for _, accepted := range routes.AcceptAllProfiles {
		fmt.Fprintf(table, "*\t%s\t\t%s\t\n",
			accepted.ProfileName, stateLabel(accepted.State, accepted.Reason))
	}
	if routes.ReconcileError != "" {
		fmt.Fprintf(table, "!\t\t\tfailed:%s\t\n", routes.ReconcileError)
	}
	_ = table.Flush()
}

func writeSearchDomains(w io.Writer, domains controlapi.SearchDomains) {
	installed := make(map[string]controlapi.InstalledSearchDomain, len(domains.Installed))
	for _, domain := range domains.Installed {
		installed[domain.Domain] = domain
	}
	waiting := make(map[string]string, len(domains.Waiting))
	for _, domain := range domains.Waiting {
		waiting[domain.Domain] = domain.Reason
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ORDER\tDOMAIN\tPROFILE\tSTATE")
	shown := map[string]bool{}
	for i, domain := range domains.Desired {
		if active, ok := installed[domain]; ok {
			fmt.Fprintf(table, "%d\t%s\t%s\t✓\n", i+1, domain, active.ProfileName)
			shown[domain+"\x00"+active.ProfileID] = true
		} else {
			fmt.Fprintf(table, "%d\t%s\t\twaiting:%s\n", i+1, domain, waiting[domain])
		}
	}
	for _, domain := range domains.Available {
		if shown[domain.Domain+"\x00"+domain.ProfileID] {
			continue
		}
		fmt.Fprintf(table, "\t%s\t%s\t\n", domain.Domain, domain.ProfileName)
	}
	if domains.ReconcileError != "" {
		fmt.Fprintf(table, "!\t\t\tfailed:%s\n", domains.ReconcileError)
	}
	_ = table.Flush()
}

func writeIPMutationResult(w io.Writer, result controlapi.IPRoutes, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(w, result)
	}
	writeIPRoutes(w, result, false)
	return nil
}

func writeDNSMutationResult(w io.Writer, result controlapi.DNSRoutes, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(w, result)
	}
	writeDNSRoutes(w, result, false)
	return nil
}

func resolverList(resolvers []controlapi.DNSResolver) string {
	values := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		values = append(values, resolver.Addr)
	}
	return strings.Join(values, ",")
}

func prefixLabel(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func stateLabel(state, reason string) string {
	if state == "installed" {
		if reason == "" {
			return "✓"
		}
		return "✓ " + reason
	}
	if reason == "" {
		return state
	}
	return state + ":" + reason
}

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "--help"
}

const rootHelp = `tailmix manages multiple Tailscale profiles on one host.

Usage:
  tailmix [--socket-dir <directory>] <command> [arguments]

Commands:
  status       Show active profiles and accepted network policy
  update       Manage automatic binary updates
  profiles     Manage profile lifecycle and configuration
  routes       Accept IP routes and pin prefixes to profiles
  exit-node    Select one profile's exit node for default traffic
  dns routes   Route DNS suffixes through selected profiles
  dns search   Manage the ordered OS search-domain list
  tailscale    Run an upstream Tailscale command for one profile
  ts           Shortcut for tailscale
  completion   Generate shell completion scripts
  version      Show the tailmix build version
  help         Show this help

Use "tailmix <command> help" for command-specific help.

Environment:
  TAILMIX_SOCKET_DIR   Default directory for daemon and profile sockets
`

const versionHelp = `Usage:
  tailmix version

Shows client and server versions, source revisions, and full embedded Tailscale
module versions. The server is shown as unavailable when tailmixd cannot be
reached.
`

const updateHelp = `Usage:
  tailmix update status [--json]
  tailmix update enable [--json]
  tailmix update disable [--json]
  tailmix update check [--json]
  tailmix update apply [--json]

Automatic updates are enabled by default. Check queries the stable release
channel immediately; apply installs an available update immediately.
`

const statusHelp = `Usage:
  tailmix status [--json]

Shows active profiles and the accepted IP routes, selected exit node, effective
DNS routes, and configured DNS search domains. Advertised-but-unaccepted choices
remain available through the corresponding list commands.
`

const profilesHelp = `Usage:
  tailmix profiles list [--all] [--json]
  tailmix profiles show <profile> [--json]
  tailmix profiles add <profile> [options]
  tailmix profiles rename <profile> <new-profile>
  tailmix profiles set <profile> --hostname <hostname> [--json]
  tailmix profiles enable <profile> [--json]
  tailmix profiles disable <profile> [--json]
  tailmix profiles restart <profile> [--json]
  tailmix profiles remove <profile> [--purge --yes] [--json]

Add options:
  --hostname <hostname>
  --state-dir <directory>
  --auth-key-env <variable>
  --auth-key-file <path|->
  --disabled
  --json
`

const routesHelp = `Usage:
  tailmix routes list [--available] [--json]
  tailmix routes bind --profile <profile> <prefix>... [--replace] [--json]
  tailmix routes unbind <prefix>... [--profile <expected-profile>] [--json]
  tailmix routes set --profile <profile> --accept-all=<true|false> [--json]

Profile option: -p, --profile <profile>

Bindings are explicit overrides: the longest matching binding wins before any
accept-all import. Overridden and conflicting imports are shown by "routes list".
The default list also includes every detected route; --available shows only
detected routes.
Default routes use exit-node policy.
`

const exitNodeHelp = `Usage:
  tailmix exit-node list [--filter <country>] [--json]
  tailmix exit-node set --profile <profile> <peer> [--json]
  tailmix exit-node clear [--json]

Profile option: -p, --profile <profile>

The peer may be an exit node's DNS name, short hostname, stable node ID, or
Tailscale IP. Only one exit node can be selected across all profiles. Explicit
peer and subnet routes keep precedence over the selected default route.

The default list shows the highest-priority node per city, an "Any" choice for
countries with multiple cities, every node without location metadata, and any
selected node hidden by those rules. Use --filter with a country name to show
every exit node in that country.
`

const dnsHelp = `Usage:
  tailmix dns routes <command> [arguments]
  tailmix dns search <command> [arguments]
`

const dnsRoutesHelp = `Usage:
  tailmix dns routes list [--available] [--json]
  tailmix dns routes bind --profile <profile> <domain>... [--replace] [--json]
  tailmix dns routes unbind <domain>... [--profile <expected-profile>] [--json]
  tailmix dns routes set --profile <profile> --accept-all=<true|false> [--json]

Profile option: -p, --profile <profile>

Bindings are explicit overrides: the longest matching binding wins before any
accept-all import or automatic MagicDNS route. Overridden and conflicting
imports are shown by "dns routes list".
The default list also includes every detected DNS route; --available shows only
detected routes.
The root suffix "." selects a profile's default DNS resolver route.
`

const dnsSearchHelp = `Usage:
  tailmix dns search list [--json]
  tailmix dns search set <domain>... [--json]
  tailmix dns search add <domain>... [--json]
  tailmix dns search remove <domain>... [--json]
  tailmix dns search clear [--json]

The list includes configured search domains and every search domain detected
from each tailnet.
`

const tailscaleHelp = `Usage:
  tailmix tailscale --profile <profile> <tailscale-subcommand> [arguments]
  tailmix ts --profile <profile> <tailscale-subcommand> [arguments]

Profile option: -p, --profile <profile>

All remaining arguments are passed unchanged to Tailscale's upstream CLI.
The --socket option is owned by tailmix and cannot be overridden.
`
