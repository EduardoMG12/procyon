// Command procyon is automatic security QA for APIs.
package main

import (
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
	if len(args) != 1 {
		fmt.Fprintf(stderr, "procyon lint: expected exactly one spec file\n\n%s", usage)
		return exitUsage
	}
	report, err := lint.Run(args[0], lint.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "procyon: %v\n", err)
		return exitUsage
	}
	if err := format.Terminal(stdout, report, format.TerminalOptions{Color: useColor(stdout)}); err != nil {
		fmt.Fprintf(stderr, "procyon: writing report: %v\n", err)
		return exitUsage
	}
	if report.Failed {
		return exitFail
	}
	return exitPass
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
  procyon lint <spec>   Check an OpenAPI 3 spec for security problems
  procyon --version     Print the version

Exit codes: 0 passed, 1 findings at or above the fail threshold, 2 usage or input error.
`
