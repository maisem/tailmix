package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	statePath := flag.String("state", "/var/lib/mnet/state.json", "path to mnet daemon state")
	flag.Parse()
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "state path is required")
		os.Exit(2)
	}
	fmt.Printf("mnetd state=%s\n", *statePath)
}
