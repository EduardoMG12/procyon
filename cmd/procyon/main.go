// Command procyon is automatic security QA for APIs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/test"
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

// command is what differs between lint and test: their extra flags and
// how they produce a report. Flags shared by both (--fail-on, --format,
// --output, --ref-root), .procyon.yaml, formats and exit codes are handled
// once, in runCommand.
type command struct {
	name  string
	flags func(*flag.FlagSet) // registers the command's own flags, or nil
	run   func(spec string, failOn lint.Severity, refRoot string, cfg config) (lint.Report, error)
}

var lintCommand = command{
	name: "lint",
	run: func(spec string, failOn lint.Severity, refRoot string, _ config) (lint.Report, error) {
		return lint.Run(spec, lint.Options{FailOn: failOn, RefRoot: refRoot})
	},
}

func testCommand() command {
	var baseURL, composeFile, service, baseSpec string
	var port int
	return command{
		name: "test",
		flags: func(f *flag.FlagSet) {
			f.StringVar(&baseURL, "base-url", "", "")
			f.StringVar(&composeFile, "compose", "", "")
			f.StringVar(&service, "service", "", "")
			f.IntVar(&port, "port", 0, "")
			f.StringVar(&baseSpec, "base-spec", "", "")
		},
		run: func(spec string, failOn lint.Severity, refRoot string, cfg config) (report lint.Report, err error) {
			switch {
			case composeFile != "" && baseURL != "":
				return lint.Report{}, errors.New("--compose and --base-url: give one, not both")
			case composeFile != "" && (service == "" || port == 0):
				return lint.Report{}, errors.New("--compose needs --service (the service that serves the API) and --port (its port in the container)")
			case composeFile == "" && baseURL == "":
				return lint.Report{}, errors.New("--compose or --base-url is required: where the copy of your API under test runs")
			}
			// Ctrl-C cancels the run; the environment is still torn down.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if composeFile != "" {
				var down func() error
				baseURL, down, err = test.Up(ctx, test.Compose{File: composeFile, Service: service, Port: port})
				defer func() {
					if downErr := down(); downErr != nil && err == nil {
						err = fmt.Errorf("the tests ran, but the environment was left running: %w", downErr)
					}
				}()
				if err != nil {
					return lint.Report{}, err
				}
			}
			return test.Run(ctx, spec, test.Options{
				BaseURL: baseURL, FailOn: failOn, RefRoot: refRoot,
				TokenA: os.Getenv("PROCYON_USER_A_TOKEN"), TokenB: os.Getenv("PROCYON_USER_B_TOKEN"),
				IDs:    cfg.Test.IDs,
				LoginA: cfg.Test.Accounts.A.Login, LoginB: cfg.Test.Accounts.B.Login,
				BaseSpec: baseSpec,
			})
		},
	}
}

func runCommand(cmd command, args []string, stdout, stderr io.Writer) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}

	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard) // errors are printed below, once
	failOn := flags.String("fail-on", cfg.FailOn, "")
	defaultFormat := "terminal"
	if cfg.Format != "" {
		defaultFormat = cfg.Format
	}
	stdoutFormat := flags.String("format", defaultFormat, "")
	refRoot := flags.String("ref-root", cfg.RefRoot, "")
	var extra outputs
	flags.Var(&extra, "output", "")
	if cmd.flags != nil {
		cmd.flags(flags)
	}
	specs, err := parseInterspersed(flags, args)
	if err != nil {
		fmt.Fprintf(stderr, "procyon %s: %v\n\n%s", cmd.name, err, usage)
		return exitUsage
	}
	if len(specs) != 1 {
		fmt.Fprintf(stderr, "procyon %s: expected exactly one spec file\n\n%s", cmd.name, usage)
		return exitUsage
	}
	// --output flags replace the file's outputs instead of adding to them,
	// like every other flag wins over the file.
	if len(extra) == 0 {
		extra = cfg.outputs
	}

	if formats[*stdoutFormat] == nil {
		fmt.Fprintf(stderr, "procyon: --format: unknown format %q (use %s)\n", *stdoutFormat, formatNames())
		return exitUsage
	}

	var threshold lint.Severity
	if *failOn != "" {
		if threshold, err = lint.ParseSeverity(*failOn); err != nil {
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

	report, err := cmd.run(specs[0], threshold, *refRoot, cfg)
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
                              or markdown. Can also be set as format in
                              .procyon.yaml.
    --output <format>=<path>  Also write a format to a file. Repeatable. Can
                              also be set as a list, output, in .procyon.yaml.
    --ref-root <dir>          Let $refs read files anywhere under dir, not only
                              in the spec's directory (for monorepos). Can also
                              be set as ref-root in .procyon.yaml.
  procyon test [flags] (--compose <file> --service <name> --port <port> | --base-url <url>) <spec>
                        Call a running, disposable copy of the API and report
                        what it let an anonymous caller do. Takes the same
                        flags as lint.

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
