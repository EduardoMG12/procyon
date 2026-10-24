package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/lint"
)

// render writes a report in one format. color is true only for a terminal.
type render func(w io.Writer, report lint.Report, color bool) error

var formats = map[string]render{
	"terminal": func(w io.Writer, r lint.Report, color bool) error {
		return format.Terminal(w, r, format.TerminalOptions{Color: color})
	},
	"json": func(w io.Writer, r lint.Report, _ bool) error { return format.JSON(w, r) },
	"sarif": func(w io.Writer, r lint.Report, _ bool) error {
		// GitHub resolves paths against the repository root, which is where
		// CI runs Procyon.
		wd, _ := os.Getwd()
		return format.SARIF(w, r, wd, lint.Rules())
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
	name, path, ok := strings.Cut(value, "=")
	if !ok || path == "" {
		return fmt.Errorf("--output %q: want format=path, for example json=report.json", value)
	}
	if formats[name] == nil {
		return fmt.Errorf("--output %q: unknown format %q (use %s)", value, name, formatNames())
	}
	*o = append(*o, output{name, path})
	return nil
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
