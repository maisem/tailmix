package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	mnetdns "tailscale.com/mnet/dns"
	mnetstatus "tailscale.com/mnet/status"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: mnet status --json | mnet resolve <name>")
		return 2
	}
	switch args[0] {
	case "status":
		if len(args) != 2 || args[1] != "--json" {
			fmt.Fprintln(stderr, "usage: mnet status --json")
			return 2
		}
		b, err := json.MarshalIndent(mnetstatus.Status{Profiles: []mnetstatus.Profile{}}, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	case "resolve":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: mnet resolve <explicit-name>")
			return 2
		}
		_, err := mnetdns.NewResolver(nil).Resolve(args[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}
