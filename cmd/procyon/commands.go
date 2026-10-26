package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/probe"
	"github.com/EduardoMG12/procyon/internal/report"
)

// command is what differs between lint and test: their extra flags and
// how they produce a report. Flags shared by both (--fail-on, --format,
// --output, --ref-root), .procyon.yaml, formats and exit codes are handled
// once, in runCommand.
type command struct {
	name  string
	flags func(*flag.FlagSet) // registers the command's own flags, or nil
	run   func(spec string, common invocation) (report.Report, error)
	// inputs are the files the command reads besides the spec, which no
	// --output may overwrite, or nil.
	inputs func() []string
}

// invocation is what the shared flags and .procyon.yaml decided for one
// run.
type invocation struct {
	cfg     config
	failOn  report.Severity
	refRoot string
	format  string  // what to print
	outputs outputs // what to write to files
}

var lintCommand = command{
	name: "lint",
	run: func(spec string, in invocation) (report.Report, error) {
		return lint.Run(spec, lint.Options{FailOn: in.failOn, RefRoot: in.refRoot})
	},
}

// testFlags are procyon test's own flags.
type testFlags struct {
	baseURL, compose, service, baseSpec string
	port                                int
}

func testCommand() command {
	var tf testFlags
	return command{
		name: "test",
		flags: func(f *flag.FlagSet) {
			f.StringVar(&tf.baseURL, "base-url", "", "")
			f.StringVar(&tf.compose, "compose", "", "")
			f.StringVar(&tf.service, "service", "", "")
			f.IntVar(&tf.port, "port", 0, "")
			f.StringVar(&tf.baseSpec, "base-spec", "", "")
		},
		run:    func(spec string, in invocation) (report.Report, error) { return runTest(spec, in, tf) },
		inputs: func() []string { return []string{tf.baseSpec} },
	}
}

// runTest starts the environment when --compose asks for one, runs the
// runtime tests and always tears the environment down, even on Ctrl-C.
func runTest(spec string, in invocation, tf testFlags) (rep report.Report, err error) {
	switch {
	case tf.compose != "" && tf.baseURL != "":
		return report.Report{}, errors.New("--compose and --base-url: give one, not both")
	case tf.compose != "" && (tf.service == "" || tf.port == 0):
		return report.Report{}, errors.New("--compose needs --service (the service that serves the API) and --port (its port in the container)")
	case tf.compose == "" && tf.baseURL == "":
		return report.Report{}, errors.New("--compose or --base-url is required: where the copy of your API under test runs")
	case tf.compose == "" && (tf.service != "" || tf.port != 0):
		return report.Report{}, errors.New("--service and --port go with --compose; with --base-url, the URL says where the API is")
	}
	// A base spec that does not load is a note (the change may have broken
	// it); a path that does not exist is a typo, which would quietly test
	// every operation instead of the changed ones.
	if tf.baseSpec != "" {
		if _, err := os.Stat(tf.baseSpec); err != nil {
			return report.Report{}, fmt.Errorf("--base-spec: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	baseURL := tf.baseURL
	if tf.compose != "" {
		var down func() error
		baseURL, down, err = probe.Up(ctx, probe.Compose{File: tf.compose, Service: tf.service, Port: tf.port})
		defer func() { err = withDown(err, down()) }()
		if err != nil {
			return report.Report{}, err
		}
	}
	cfg := in.cfg.Test
	return probe.Run(ctx, spec, probe.Options{
		BaseURL: baseURL, FailOn: in.failOn, RefRoot: in.refRoot,
		TokenA: os.Getenv(probe.EnvTokenA), TokenB: os.Getenv(probe.EnvTokenB),
		LoginA: cfg.Accounts.A.Login, LoginB: cfg.Accounts.B.Login,
		IDs: cfg.IDs, Skip: cfg.Skip, BaseSpec: tf.baseSpec,
	})
}

// errLeftRunning is a teardown that failed after the tests ran: the report
// is still printed, then the warning, and the exit code is 2.
var errLeftRunning = errors.New("the tests ran, but the environment was left running")

// withDown adds a failed teardown to a run's error: the user must hear the
// environment may still be up.
func withDown(err, downErr error) error {
	switch {
	case downErr == nil:
		return err
	case err == nil:
		return fmt.Errorf("%w: %w", errLeftRunning, downErr)
	}
	return errors.Join(err, fmt.Errorf("and the environment may be left running: %w", downErr))
}

// runCommand runs a command and returns its exit code.
func runCommand(cmd command, args []string, stdout, stderr io.Writer) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	spec, in, err := parseCommon(cmd, args, cfg)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, usage)
		return exitPass
	}
	if err != nil {
		// Some end with the usage text, which ends its own line.
		fmt.Fprint(stderr, strings.TrimSuffix(err.Error(), "\n")+"\n")
		return exitUsage
	}
	// Output files are created before the run, so a path that cannot be
	// written stops it before anything is printed.
	inputs := []string{spec}
	if cmd.inputs != nil {
		inputs = append(inputs, cmd.inputs()...)
	}
	files, err := openOutputs(in.outputs, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	defer closeAll(files)

	rep, runErr := cmd.run(spec, in)
	if runErr != nil && !errors.Is(runErr, errLeftRunning) {
		fmt.Fprintf(stderr, "procyon: %v\n", runErr)
		return exitUsage
	}
	if err := writeReport(rep, in, stdout, files); err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	if runErr != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", runErr)
		return exitUsage
	}
	if rep.Failed {
		return exitFail
	}
	return exitPass
}

// parseCommon reads the flags every command shares, then the command's
// own, over the defaults from .procyon.yaml: flags win. Its errors are
// ready to print.
func parseCommon(cmd command, args []string, cfg config) (string, invocation, error) {
	in := invocation{cfg: cfg, format: "terminal"}
	if cfg.Format != "" {
		in.format = cfg.Format
	}
	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard) // errors are printed by the caller, once
	failOn := flags.String("fail-on", cfg.FailOn, "")
	flags.StringVar(&in.format, "format", in.format, "")
	flags.StringVar(&in.refRoot, "ref-root", cfg.RefRoot, "")
	flags.Var(&in.outputs, "output", "")
	if cmd.flags != nil {
		cmd.flags(flags)
	}
	specs, err := parseInterspersed(flags, args)
	if errors.Is(err, flag.ErrHelp) {
		return "", in, err
	}
	if err != nil {
		return "", in, fmt.Errorf("procyon %s: %v\n\n%s", cmd.name, err, usage)
	}
	if len(specs) != 1 {
		return "", in, fmt.Errorf("procyon %s: expected exactly one spec file\n\n%s", cmd.name, usage)
	}
	// --output flags replace the file's outputs instead of adding to them,
	// like every other flag wins over the file.
	if len(in.outputs) == 0 {
		in.outputs = cfg.outputs
	}
	if formats[in.format] == nil {
		return "", in, fmt.Errorf("procyon: --format: unknown format %q (use %s)", in.format, formatNames())
	}
	if *failOn != "" {
		if in.failOn, err = report.ParseSeverity(*failOn); err != nil {
			return "", in, fmt.Errorf("procyon: --fail-on: %v", err)
		}
	}
	return specs[0], in, nil
}

// writeReport prints the report in the chosen format, coloured only on a
// terminal, and writes each --output file.
func writeReport(rep report.Report, in invocation, stdout io.Writer, files []*os.File) error {
	color := in.format == "terminal" && useColor(stdout)
	if err := formats[in.format](stdout, rep, color); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	for i, o := range in.outputs {
		err := formats[o.format](files[i], rep, false) // files never get colours
		if err == nil {
			err = files[i].Close()
		}
		if err != nil {
			return fmt.Errorf("--output %s=%s: %w", o.format, o.path, err)
		}
	}
	return nil
}
