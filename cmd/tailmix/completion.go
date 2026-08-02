package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"tailscale.com/cmd/tailscale/cli"
	"tailscale.com/tempfork/spf13/cobra"
)

type completionValueKind int

const (
	completionNoValue completionValueKind = iota
	completionFreeValue
	completionProfile
	completionBoolean
	completionFile
	completionDirectory
)

type completionFlag struct {
	names       []string
	description string
	value       completionValueKind
}

type completionCommand struct {
	name        string
	description string
	flags       []completionFlag
	subcommands []*completionCommand
	arguments   []completionValueKind
	variadic    completionValueKind
	help        bool
}

type completionCandidate struct {
	value       string
	description string
}

func runCompletion(ctx context.Context, socketDir string, args []string, deps dependencies) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(deps.stdout, completionHelp)
		return nil
	}

	switch args[0] {
	case "bash", "zsh", "fish", "powershell", "pwsh":
		if err := noOperands(args[1:]); err != nil {
			return err
		}
		return writeCompletionScript(deps.stdout, args[0])
	case "__complete":
		words := args[1:]
		if len(words) > 0 && words[0] == "--" {
			words = words[1:]
		}
		if delegateTailscaleCompletion(ctx, socketDir, words, deps) {
			return nil
		}
		candidates, directive := completeTailmix(ctx, socketDir, words, deps)
		writeCompletionCandidates(deps.stdout, candidates, directive)
		return nil
	default:
		return usageError{fmt.Sprintf("unsupported shell %q; choose bash, zsh, fish, or powershell", args[0])}
	}
}

func writeCompletionScript(w io.Writer, shell string) error {
	const (
		name    = "tailmix"
		command = "completion __complete --"
	)
	switch shell {
	case "bash":
		return cobra.ScriptBash(w, name, command, name)
	case "zsh":
		return cobra.ScriptZsh(w, name, command, name)
	case "fish":
		return cobra.ScriptFish(w, name, command, name)
	case "powershell", "pwsh":
		return cobra.ScriptPowershell(w, name, command, name)
	default:
		return fmt.Errorf("unsupported completion shell %q", shell)
	}
}

func delegateTailscaleCompletion(ctx context.Context, socketDir string, words []string, deps dependencies) bool {
	if deps.runCLI == nil || deps.newClient == nil {
		return false
	}

	innerSocketDir, commandIndex := completionSocketDir(socketDir, words)
	if commandIndex >= len(words) || (words[commandIndex] != "tailscale" && words[commandIndex] != "ts") {
		return false
	}
	profileName, rest, set, err := takeLeadingProfile(words[commandIndex+1:])
	if err != nil || !set || profileName == "" || len(rest) == 0 {
		return false
	}
	selected, err := deps.newClient(innerSocketDir).Profile(ctx, profileName)
	if err != nil {
		return false
	}
	socketPath, err := profileLocalAPISocket(innerSocketDir, selected)
	if err != nil {
		return false
	}

	args := []string{"--socket=" + socketPath, "completion", "__complete", "--"}
	args = append(args, rest...)
	oldStdout, oldStderr := cli.Stdout, cli.Stderr
	cli.Stdout, cli.Stderr = deps.stdout, deps.stderr
	defer func() {
		cli.Stdout, cli.Stderr = oldStdout, oldStderr
	}()
	return deps.runCLI(ctx, args) == nil
}

func completionSocketDir(fallback string, words []string) (string, int) {
	if len(words) == 0 {
		return fallback, 0
	}
	if strings.HasPrefix(words[0], "--socket-dir=") {
		value := strings.TrimSpace(strings.TrimPrefix(words[0], "--socket-dir="))
		if value != "" {
			fallback = value
		}
		return fallback, 1
	}
	if words[0] == "--socket-dir" {
		if len(words) > 1 {
			if value := strings.TrimSpace(words[1]); value != "" {
				fallback = value
			}
			return fallback, 2
		}
		return fallback, 1
	}
	return fallback, 0
}

func completeTailmix(ctx context.Context, socketDir string, words []string, deps dependencies) ([]completionCandidate, cobra.ShellCompDirective) {
	if len(words) == 0 {
		words = []string{""}
	}
	currentWord := words[len(words)-1]
	command, positionals, used, pending := scanCompletionCommand(completionCommandTree(), words[:len(words)-1])
	if pending != completionNoValue {
		return completeValue(ctx, completionSocketForWords(socketDir, words), pending, currentWord, deps)
	}
	if name, value, ok := strings.Cut(currentWord, "="); ok {
		if flag := findCompletionFlag(command, name); flag != nil && flag.value != completionNoValue {
			return completeValue(ctx, completionSocketForWords(socketDir, words), flag.value, value, deps)
		}
	}

	var candidates []completionCandidate
	if currentWord == "" || strings.HasPrefix(currentWord, "-") {
		for i := range command.flags {
			flag := &command.flags[i]
			if used[flag.names[0]] {
				continue
			}
			for _, name := range flag.names {
				if strings.HasPrefix(name, currentWord) {
					candidates = append(candidates, completionCandidate{name, flag.description})
				}
			}
		}
	}
	if !strings.HasPrefix(currentWord, "-") && len(positionals) == 0 {
		for _, subcommand := range command.subcommands {
			if strings.HasPrefix(subcommand.name, currentWord) {
				candidates = append(candidates, completionCandidate{subcommand.name, subcommand.description})
			}
		}
		if command.help && strings.HasPrefix("help", currentWord) {
			candidates = append(candidates, completionCandidate{"help", "Show command help"})
		}
	}
	if !strings.HasPrefix(currentWord, "-") {
		if kind := completionArgumentKind(command, len(positionals)); kind != completionNoValue {
			values, _ := completeValue(ctx, completionSocketForWords(socketDir, words), kind, currentWord, deps)
			candidates = append(candidates, values...)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].value < candidates[j].value
	})
	return candidates, cobra.ShellCompDirectiveNoFileComp
}

func completionSocketForWords(fallback string, words []string) string {
	dir, _ := completionSocketDir(fallback, words)
	return dir
}

func scanCompletionCommand(root *completionCommand, words []string) (command *completionCommand, positionals []string, used map[string]bool, pending completionValueKind) {
	command = root
	used = make(map[string]bool)
	for i := 0; i < len(words); i++ {
		word := words[i]
		name, _, inline := strings.Cut(word, "=")
		if flag := findCompletionFlag(command, name); flag != nil {
			used[flag.names[0]] = true
			if flag.value == completionNoValue || inline {
				continue
			}
			if i+1 == len(words) {
				return command, positionals, used, flag.value
			}
			i++
			continue
		}
		if len(positionals) == 0 {
			if subcommand := findCompletionSubcommand(command, word); subcommand != nil {
				command = subcommand
				continue
			}
		}
		positionals = append(positionals, word)
	}
	return command, positionals, used, completionNoValue
}

func findCompletionFlag(command *completionCommand, name string) *completionFlag {
	for i := range command.flags {
		for _, candidate := range command.flags[i].names {
			if candidate == name {
				return &command.flags[i]
			}
		}
	}
	return nil
}

func findCompletionSubcommand(command *completionCommand, name string) *completionCommand {
	for _, subcommand := range command.subcommands {
		if subcommand.name == name {
			return subcommand
		}
	}
	return nil
}

func completionArgumentKind(command *completionCommand, index int) completionValueKind {
	if index < len(command.arguments) {
		return command.arguments[index]
	}
	return command.variadic
}

func completeValue(ctx context.Context, socketDir string, kind completionValueKind, prefix string, deps dependencies) ([]completionCandidate, cobra.ShellCompDirective) {
	switch kind {
	case completionProfile:
		if deps.newClient == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		profiles, err := deps.newClient(socketDir).Profiles(ctx, true)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		candidates := make([]completionCandidate, 0, len(profiles.Profiles))
		for _, profile := range profiles.Profiles {
			if !strings.HasPrefix(profile.Name, prefix) {
				continue
			}
			description := strings.TrimSpace(profile.RuntimeState)
			if description == "" {
				description = "profile"
			}
			candidates = append(candidates, completionCandidate{profile.Name, description})
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].value < candidates[j].value })
		return candidates, cobra.ShellCompDirectiveNoFileComp
	case completionBoolean:
		var candidates []completionCandidate
		for _, value := range []string{"false", "true"} {
			if strings.HasPrefix(value, prefix) {
				candidates = append(candidates, completionCandidate{value, "boolean value"})
			}
		}
		return candidates, cobra.ShellCompDirectiveNoFileComp
	case completionFile:
		return nil, cobra.ShellCompDirectiveDefault
	case completionDirectory:
		return nil, cobra.ShellCompDirectiveFilterDirs
	default:
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

func writeCompletionCandidates(w io.Writer, candidates []completionCandidate, directive cobra.ShellCompDirective) {
	for _, candidate := range candidates {
		value := cleanCompletionText(candidate.value)
		if value == "" {
			continue
		}
		description := cleanCompletionText(candidate.description)
		if description == "" {
			fmt.Fprintln(w, value)
		} else {
			fmt.Fprintf(w, "%s\t%s\n", value, description)
		}
	}
	fmt.Fprintf(w, ":%d\n", directive)
}

func cleanCompletionText(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			return r
		}
	}, value)
}

func completionCommandTree() *completionCommand {
	flag := func(description string, value completionValueKind, names ...string) completionFlag {
		return completionFlag{names: names, description: description, value: value}
	}
	jsonFlag := func() completionFlag { return flag("Write JSON output", completionNoValue, "--json") }
	profileFlag := func() completionFlag {
		return flag("Select a tailmix profile", completionProfile, "-p", "--profile")
	}
	leaf := func(name, description string, flags []completionFlag, arguments ...completionValueKind) *completionCommand {
		return &completionCommand{name: name, description: description, flags: flags, arguments: arguments}
	}

	profiles := &completionCommand{
		name: "profiles", description: "Manage profile lifecycle and configuration", help: true,
		subcommands: []*completionCommand{
			leaf("list", "List configured profiles", []completionFlag{flag("Include removed profiles", completionNoValue, "--all"), jsonFlag()}),
			leaf("show", "Show one profile", []completionFlag{jsonFlag()}, completionProfile),
			leaf("add", "Add a profile", []completionFlag{
				flag("Set the advertised hostname", completionFreeValue, "--hostname"),
				flag("Set the profile state directory", completionDirectory, "--state-dir"),
				flag("Read an auth key from an environment variable", completionFreeValue, "--auth-key-env"),
				flag("Read an auth key from a file", completionFile, "--auth-key-file"),
				flag("Add the profile disabled", completionNoValue, "--disabled"), jsonFlag(),
			}, completionFreeValue),
			leaf("rename", "Rename a profile", nil, completionProfile, completionFreeValue),
			leaf("set", "Change profile configuration", []completionFlag{flag("Set the advertised hostname", completionFreeValue, "--hostname"), jsonFlag()}, completionProfile),
			leaf("enable", "Enable a profile", []completionFlag{jsonFlag()}, completionProfile),
			leaf("disable", "Disable a profile", []completionFlag{jsonFlag()}, completionProfile),
			leaf("restart", "Restart a profile", []completionFlag{jsonFlag()}, completionProfile),
			leaf("remove", "Remove a profile", []completionFlag{
				flag("Delete retained identity and bindings", completionNoValue, "--purge"),
				flag("Confirm a purge without prompting", completionNoValue, "--yes"), jsonFlag(),
			}, completionProfile),
		},
	}

	routes := &completionCommand{
		name: "routes", description: "Accept IP routes and pin prefixes to profiles", help: true,
		subcommands: []*completionCommand{
			leaf("list", "List IP routes", []completionFlag{flag("Show only advertised routes", completionNoValue, "--available"), jsonFlag()}),
			{name: "bind", description: "Bind prefixes to a profile", flags: []completionFlag{profileFlag(), flag("Replace conflicting bindings", completionNoValue, "--replace"), jsonFlag()}, variadic: completionFreeValue},
			{name: "unbind", description: "Remove prefix bindings", flags: []completionFlag{profileFlag(), jsonFlag()}, variadic: completionFreeValue},
			leaf("set", "Set profile-wide IP route policy", []completionFlag{profileFlag(), flag("Accept every advertised route", completionBoolean, "--accept-all"), jsonFlag()}),
		},
	}

	exitNode := &completionCommand{
		name: "exit-node", description: "Select one profile's exit node for default traffic", help: true,
		subcommands: []*completionCommand{
			leaf("list", "List exit nodes", []completionFlag{flag("Filter by country", completionFreeValue, "--filter"), jsonFlag()}),
			leaf("set", "Select an exit node", []completionFlag{profileFlag(), jsonFlag()}, completionFreeValue),
			leaf("clear", "Clear the selected exit node", []completionFlag{jsonFlag()}),
		},
	}

	dnsRoutes := &completionCommand{
		name: "routes", description: "Manage DNS route policy", help: true,
		subcommands: []*completionCommand{
			leaf("list", "List DNS routes", []completionFlag{flag("Show only advertised routes", completionNoValue, "--available"), jsonFlag()}),
			{name: "bind", description: "Bind DNS suffixes to a profile", flags: []completionFlag{profileFlag(), flag("Replace conflicting bindings", completionNoValue, "--replace"), jsonFlag()}, variadic: completionFreeValue},
			{name: "unbind", description: "Remove DNS route bindings", flags: []completionFlag{profileFlag(), jsonFlag()}, variadic: completionFreeValue},
			leaf("set", "Set profile-wide DNS route policy", []completionFlag{profileFlag(), flag("Accept every advertised DNS route", completionBoolean, "--accept-all"), jsonFlag()}),
		},
	}
	dnsSearch := &completionCommand{
		name: "search", description: "Manage the ordered OS search-domain list", help: true,
		subcommands: []*completionCommand{
			leaf("list", "List DNS search domains", []completionFlag{jsonFlag()}),
			{name: "set", description: "Replace DNS search domains", flags: []completionFlag{jsonFlag()}, variadic: completionFreeValue},
			{name: "add", description: "Add DNS search domains", flags: []completionFlag{jsonFlag()}, variadic: completionFreeValue},
			{name: "remove", description: "Remove DNS search domains", flags: []completionFlag{jsonFlag()}, variadic: completionFreeValue},
			leaf("clear", "Clear DNS search domains", []completionFlag{jsonFlag()}),
		},
	}
	dns := &completionCommand{
		name: "dns", description: "Manage DNS routing and search domains", help: true,
		subcommands: []*completionCommand{dnsRoutes, dnsSearch},
	}

	completion := &completionCommand{
		name: "completion", description: "Generate shell completion scripts", help: true,
		subcommands: []*completionCommand{
			leaf("bash", "Generate a Bash completion script", nil),
			leaf("zsh", "Generate a Zsh completion script", nil),
			leaf("fish", "Generate a fish completion script", nil),
			leaf("powershell", "Generate a PowerShell completion script", nil),
			leaf("pwsh", "Alias for powershell", nil),
		},
	}
	update := &completionCommand{
		name: "update", description: "Manage automatic binary updates", help: true,
		subcommands: []*completionCommand{
			leaf("status", "Show automatic update status", []completionFlag{jsonFlag()}),
			leaf("enable", "Enable automatic updates", []completionFlag{jsonFlag()}),
			leaf("disable", "Disable automatic updates", []completionFlag{jsonFlag()}),
			leaf("check", "Check for an update now", []completionFlag{jsonFlag()}),
			leaf("apply", "Apply an available update now", []completionFlag{jsonFlag()}),
		},
	}

	return &completionCommand{
		name:  "tailmix",
		flags: []completionFlag{flag("Use a different daemon socket directory", completionDirectory, "--socket-dir")},
		subcommands: []*completionCommand{
			{name: "status", description: "Show active profiles and accepted network policy", flags: []completionFlag{jsonFlag()}, help: true},
			update,
			profiles,
			routes,
			exitNode,
			dns,
			tailscaleCompletionCommand("tailscale", "Run an upstream Tailscale command for one profile", profileFlag()),
			tailscaleCompletionCommand("ts", "Shortcut for tailscale", profileFlag()),
			completion,
			{name: "version", description: "Show the tailmix build version", help: true},
			leaf("help", "Show root help", nil),
		},
	}
}

func tailscaleCompletionCommand(name, description string, profileFlag completionFlag) *completionCommand {
	commands := []string{
		"up", "down", "set", "get", "login", "logout", "switch", "configure",
		"netcheck", "ip", "dns", "status", "metrics", "ping", "nc", "ssh",
		"funnel", "serve", "service", "version", "web", "file", "bugreport",
		"cert", "lock", "licenses", "exit-node", "update", "whois", "whoami",
		"debug", "drive", "id-token", "configure-host", "systray", "appc-routes", "wait",
	}
	subcommands := make([]*completionCommand, 0, len(commands))
	for _, command := range commands {
		subcommands = append(subcommands, &completionCommand{name: command, description: "Tailscale command"})
	}
	return &completionCommand{
		name: name, description: description, flags: []completionFlag{profileFlag},
		subcommands: subcommands, help: true,
	}
}

const completionHelp = `Usage:
  tailmix completion bash
  tailmix completion zsh
  tailmix completion fish
  tailmix completion powershell
  tailmix completion pwsh

Generate a completion script for the selected shell. The scripts complete
tailmix commands and flags, configured profile names, and delegated Tailscale
commands after a profile has been selected.
`
