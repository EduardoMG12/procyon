package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
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
