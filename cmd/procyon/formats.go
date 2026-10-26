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
// and a run that fails never leaves an earlier run's report behind. It
// refuses a path that is one of the inputs (the spec, --base-spec) or
// another output: creating it would empty the spec, or two formats would
// write over each other.
func openOutputs(outs outputs, inputs []string) ([]*os.File, error) {
	var ins, opened []os.FileInfo
	for _, path := range inputs {
		if info, err := os.Stat(path); err == nil {
			ins = append(ins, info)
		}
	}
	same := func(infos []os.FileInfo, info os.FileInfo) bool {
		return slices.ContainsFunc(infos, func(other os.FileInfo) bool { return os.SameFile(other, info) })
	}
	files := make([]*os.File, 0, len(outs))
	fail := func(o output, why string) ([]*os.File, error) {
		closeAll(files)
		return nil, fmt.Errorf("--output %s=%s: %s", o.format, o.path, why)
	}
	for _, o := range outs {
		// A committed symlink named like a report would make Procyon write
		// through it, over whatever it points at.
		if info, err := os.Lstat(o.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fail(o, "a symbolic link; give the report's own path")
		}
		if info, err := os.Stat(o.path); err == nil && same(ins, info) {
			return fail(o, "this is an input file; writing the report there would erase it")
		}
		file, err := os.Create(o.path)
		if err != nil {
			return fail(o, err.Error())
		}
		files = append(files, file)
		info, err := file.Stat()
		if err != nil {
			return fail(o, err.Error())
		}
		if same(opened, info) {
			return fail(o, "another --output already writes there")
		}
		opened = append(opened, info)
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}
