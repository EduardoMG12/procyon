// Command procyon is automatic security QA for APIs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Exit codes. Scripts tell "Procyon found problems" (1) apart from "Procyon
// could not run" (2).
const (
	exitPass  = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprint(stdout, usage)
		return exitPass
	case "--version", "version":
		fmt.Fprintln(stdout, versionString())
		return exitPass
	case "lint":
		return runCommand(lintCommand, args[1:], stdout, stderr)
	case "test":
		return runCommand(testCommand(), args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "procyon: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

// parseInterspersed parses flags wherever they appear, so both
// `procyon lint --fail-on low spec.yaml` and `procyon lint spec.yaml
// --fail-on low` work. The standard flag package stops at the first
// positional argument; this resumes parsing after each one.
func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		// Parse consumes "--" and stops there: everything after it is
		// positional, even if it looks like a flag.
		if len(rest) < len(args) && args[len(args)-len(rest)-1] == "--" {
			return append(positional, rest...), nil
		}
		args = rest
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// useColor reports whether w is a terminal and the user has not opted out
// with a non-empty NO_COLOR (https://no-color.org).
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

const usage = `Usage:
  procyon lint [flags] <spec>
                        Check an OpenAPI 3 or Swagger 2.0 spec for security
                        problems.

    --fail-on <severity>      critical, high (default), medium or low.
                              Can also be set as fail-on in .procyon.yaml.
    --format <format>         What to print: terminal (default), json, sarif
                              or markdown. Can also be set as format in
                              .procyon.yaml.
    --output <format>=<path>  Also write a format to a file. Repeatable. Can
                              also be set as a list, output, in .procyon.yaml.
    --ref-root <dir>          Let $refs read files anywhere under dir, not only
                              in the spec's directory (for monorepos). Can also
                              be set as ref-root in .procyon.yaml.
  procyon test [flags] (--compose <file> --service <name> --port <port> | --base-url <url>) <spec>
                        Call a running, disposable copy of the API as two test
                        accounts and anonymously, and report what each could
                        do, how it handles malformed input, and its TLS.
                        Takes the same flags as lint. Accounts, IDs and
                        operations to skip can be set under test: in
                        .procyon.yaml (docs/configuration.md).

    --compose <file>          Start a disposable copy of the API with docker
                              compose, test it, and always tear it down.
    --service <name>          The compose service that serves the API.
    --port <port>             The API's port inside that container.
    --base-url <url>          Or test a copy you started. Must be a loopback or
                              private address: never a system on the internet.
    --base-spec <file>        The spec before the change (git show
                              origin/main:openapi.yaml > base.yaml): test only
                              operations new or changed since it.
    PROCYON_USER_A_TOKEN, PROCYON_USER_B_TOKEN
                              Tokens of two test accounts seeded in the API.
  procyon --version     Print the version

Exit codes: 0 passed, 1 findings at or above the fail threshold, 2 usage or input error.
`
