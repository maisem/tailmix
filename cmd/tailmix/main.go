package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/maisem/tailmix/profilesocket"
	"tailscale.com/cmd/tailscale/cli"
)

type cliRunner func(context.Context, []string) error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, cli.RunWithContext))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, runCLI cliRunner) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "usage: tailmix <profile> <tailscale-subcommand> [arguments]")
		return 2
	}
	profileID := args[0]
	if strings.HasPrefix(profileID, "-") {
		fmt.Fprintln(stderr, "profile must be the first argument")
		return 2
	}
	subcommand := args[1:]
	for _, arg := range subcommand {
		if arg == "--socket" || arg == "-socket" || strings.HasPrefix(arg, "--socket=") || strings.HasPrefix(arg, "-socket=") {
			fmt.Fprintln(stderr, "the tailscale --socket flag is managed by tailmix")
			return 2
		}
	}
	if len(subcommand) == 1 {
		switch subcommand[0] {
		case "help":
			subcommand = []string{"--help"}
		case "-V", "--version":
			subcommand = []string{"version"}
		}
	}
	socketPath, err := profilesocket.Path(profilesocket.DefaultDir(), profileID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cliArgs := make([]string, 0, len(subcommand)+1)
	cliArgs = append(cliArgs, "--socket="+socketPath)
	cliArgs = append(cliArgs, subcommand...)

	oldStdout, oldStderr := cli.Stdout, cli.Stderr
	cli.Stdout, cli.Stderr = stdout, stderr
	defer func() {
		cli.Stdout, cli.Stderr = oldStdout, oldStderr
	}()
	if err := runCLI(ctx, cliArgs); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
