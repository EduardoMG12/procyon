// Command procyon is automatic security QA for APIs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/lint"
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
		return runLint(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "procyon: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func runLint(args []string, stdout, stderr io.Writer) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}

	flags := flag.NewFlagSet("lint", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // errors are printed below, once
	failOn := flags.String("fail-on", cfg.FailOn, "")
	specs, err := parseInterspersed(flags, args)
	if err != nil {
		fmt.Fprintf(stderr, "procyon lint: %v\n\n%s", err, usage)
		return exitUsage
	}
	if len(specs) != 1 {
		fmt.Fprintf(stderr, "procyon lint: expected exactly one spec file\n\n%s", usage)
		return exitUsage
	}

	var opts lint.Options
	if *failOn != "" {
		if opts.FailOn, err = lint.ParseSeverity(*failOn); err != nil {
			fmt.Fprintf(stderr, "procyon: --fail-on: %v\n", err)
			return exitUsage
		}
	}

	report, err := lint.Run(specs[0], opts)
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	if err := format.Terminal(stdout, report); err != nil {
		fmt.Fprintf(stderr, "procyon: writing report: %v\n", err)
		return exitUsage
	}
	if report.Failed {
		return exitFail
	}
	return exitPass
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

const usage = `Usage:
  procyon lint [--fail-on <severity>] <spec>
                        Check an OpenAPI 3 spec for security problems.
                        --fail-on: critical, high (default), medium or low.
                        Can also be set as fail-on in .procyon.yaml.
  procyon --version     Print the version

Exit codes: 0 passed, 1 findings at or above the fail threshold, 2 usage or input error.
`
