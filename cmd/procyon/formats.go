package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/report"
)

// render writes a report in one format. color is true only for a terminal.
type render func(w io.Writer, rep report.Report, color bool) error

var formats = map[string]render{
	"terminal": func(w io.Writer, r report.Report, color bool) error {
		return format.Terminal(w, r, format.TerminalOptions{Color: color})
	},
	"json":     func(w io.Writer, r report.Report, _ bool) error { return format.JSON(w, r) },
	"markdown": func(w io.Writer, r report.Report, _ bool) error { return format.Markdown(w, r) },
	"sarif": func(w io.Writer, r report.Report, _ bool) error {
		// GitHub resolves paths against the repository root, which is where
		// CI runs Procyon.
		wd, _ := os.Getwd()
		return format.SARIF(w, r, wd, slices.Concat(lint.Rules(), lint.RuntimeRules()))
	},
}

func formatNames() string {
	names := make([]string, 0, len(formats))
	for name := range formats {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// output is one --output format=path.
type output struct {
	format string
	path   string
}

// outputs collects repeated --output flags.
type outputs []output

func (o *outputs) String() string { return "" }

func (o *outputs) Set(value string) error {
	out, err := parseOutput(value)
	if err != nil {
		return fmt.Errorf("--output %w", err)
	}
	*o = append(*o, out)
	return nil
}

// parseOutput reads one format=path, from a flag or from .procyon.yaml.
func parseOutput(value string) (output, error) {
	name, path, ok := strings.Cut(value, "=")
	if !ok || path == "" {
		return output{}, fmt.Errorf("%q: want format=path, for example json=report.json", value)
	}
	if formats[name] == nil {
		return output{}, fmt.Errorf("%q: unknown format %q (use %s)", value, name, formatNames())
	}
	return output{name, path}, nil
}

// openOutputs creates (or empties) every --output file before linting, so
// a path that cannot be written stops the run before anything is printed,
// and a run that fails never leaves an earlier run's report behind.
func openOutputs(outs outputs) ([]*os.File, error) {
	files := make([]*os.File, 0, len(outs))
	for _, o := range outs {
		file, err := os.Create(o.path)
		if err != nil {
			closeAll(files)
			return nil, fmt.Errorf("--output %s=%s: %w", o.format, o.path, err)
		}
		files = append(files, file)
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}
