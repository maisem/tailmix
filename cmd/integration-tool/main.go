// Command integration-tool provides the Go fixtures used by integration scripts.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/maisem/tailmix/wireguardcfg"
)

type statusError int

func (s statusError) Error() string { return "fixture failed" }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		var status statusError
		if errors.As(err, &status) {
			os.Exit(int(status))
		}
		// Avoid including socket endpoints or fixture keys in diagnostics.
		fmt.Fprintln(os.Stderr, "integration-tool: operation failed")
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("missing operation")
	}
	switch args[0] {
	case "keygen":
		if len(args) != 1 {
			return errors.New("keygen takes no arguments")
		}
		for range 2 {
			private, err := wireguardcfg.GeneratePrivateKey()
			if err != nil {
				return err
			}
			public, err := private.Public()
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(stdout, "%s %s\n", private.String(), public.String()); err != nil {
				return err
			}
		}
		return nil
	case "effective-address":
		if len(args) != 2 {
			return errors.New("effective-address requires a profile")
		}
		return effectiveAddress(args[1], stdout)
	case "benchmark-report":
		if len(args) != 2 {
			return errors.New("benchmark-report requires a results directory")
		}
		return benchmarkReport(args[1], stdout)
	default:
		return socketTool(args, stdout, defaultSocketTimeouts)
	}
}
