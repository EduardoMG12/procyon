// Command procyon is automatic security QA for APIs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

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
	stdoutFormat := flags.String("format", "terminal", "")
	refRoot := flags.String("ref-root", cfg.RefRoot, "")
	var extra outputs
	flags.Var(&extra, "output", "")
	specs, err := parseInterspersed(flags, args)
	if err != nil {
		fmt.Fprintf(stderr, "procyon lint: %v\n\n%s", err, usage)
		return exitUsage
	}
	if len(specs) != 1 {
		fmt.Fprintf(stderr, "procyon lint: expected exactly one spec file\n\n%s", usage)
		return exitUsage
	}

	if formats[*stdoutFormat] == nil {
		fmt.Fprintf(stderr, "procyon: --format: unknown format %q (use %s)\n", *stdoutFormat, formatNames())
		return exitUsage
	}

	opts := lint.Options{RefRoot: *refRoot}
	if *failOn != "" {
		if opts.FailOn, err = lint.ParseSeverity(*failOn); err != nil {
			fmt.Fprintf(stderr, "procyon: --fail-on: %v\n", err)
			return exitUsage
		}
	}

	files, err := openOutputs(extra)
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	defer closeAll(files)

	report, err := lint.Run(specs[0], opts)
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	color := *stdoutFormat == "terminal" && useColor(stdout)
	if err := formats[*stdoutFormat](stdout, report, color); err != nil {
		fmt.Fprintf(stderr, "procyon: writing report: %v\n", err)
		return exitUsage
	}
	for i, o := range extra {
		err := formats[o.format](files[i], report, false) // files never get colours
		if err == nil {
			err = files[i].Close()
		}
		if err != nil {
			fmt.Fprintf(stderr, "procyon: --output %s=%s: %v\n", o.format, o.path, err)
			return exitUsage
		}
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
                        Check an OpenAPI 3 spec for security problems.

    --fail-on <severity>      critical, high (default), medium or low.
                              Can also be set as fail-on in .procyon.yaml.
    --format <format>         What to print: terminal (default), json, sarif
                              or markdown.
    --output <format>=<path>  Also write a format to a file. Repeatable.
    --ref-root <dir>          Let $refs read files anywhere under dir, not only
                              in the spec's directory (for monorepos). Can also
                              be set as ref-root in .procyon.yaml.
  procyon --version     Print the version

Exit codes: 0 passed, 1 findings at or above the fail threshold, 2 usage or input error.
`
