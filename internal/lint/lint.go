// Package lint checks a spec for security problems in the API's design.
package lint

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// Options control a run.
type Options struct {
	// FailOn is the fail threshold: the lowest severity that fails the run.
	// Zero means the default, High.
	FailOn Severity
	// RefRoot is the directory $refs may read files from. Empty means the
	// spec's own directory. A monorepo whose specs share files from a
	// sibling folder sets it to the repository root. It must contain the
	// spec, and it may not be the file system's root or the home directory.
	RefRoot string
	// Today decides whether an ignore has expired. Zero means now.
	Today time.Time
}

// Run lints the spec at path.
func Run(path string, opts Options) (Report, error) {
	doc, files, err := load(path, opts)
	if err != nil {
		return Report{}, err
	}
	report := Report{FailOn: opts.FailOn, Sources: files.lines}
	if report.FailOn == 0 {
		report.FailOn = High
	}
	asGiven := files.asGiven
	ignores, err := parseIgnores(doc, asGiven)
	if err != nil {
		return Report{}, err
	}
	for _, rule := range rules {
		for _, f := range rule.check(doc) {
			f.Rule = rule
			f.Location = asGiven(f.Location)
			report.Findings = append(report.Findings, f)
		}
	}
	// Same spec, same report, same order: sort by where findings point.
	slices.SortStableFunc(report.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Location.File, b.Location.File),
			cmp.Compare(a.Location.Line, b.Location.Line),
			cmp.Compare(a.Location.Column, b.Location.Column),
			cmp.Compare(a.Rule.ID, b.Rule.ID),
		)
	})
	today := opts.Today
	if today.IsZero() {
		today = time.Now()
	}
	applyIgnores(&report, ignores, today)
	for _, f := range report.Findings {
		if f.Rule.Severity >= report.FailOn {
			report.Failed = true
		}
	}
	return report, nil
}

// load reads the spec at path, recording the file, line and column of every
// element so findings can point at the original file.
func load(path string, opts Options) (*openapi3.T, *specFiles, error) {
	data, err := readSpec(path)
	if err != nil {
		return nil, nil, err
	}

	// kin-openapi's own syntax errors are off by a line for some YAML
	// mistakes and mix a JSON and a YAML message. goccy/go-yaml reports the
	// exact line and column, and reads JSON too (JSON is valid YAML).
	if _, err := parser.ParseBytes(data, 0); err != nil {
		var syntaxErr *yaml.SyntaxError
		if errors.As(err, &syntaxErr) && syntaxErr.Token != nil {
			pos := syntaxErr.Token.Position
			return nil, nil, fmt.Errorf("%s:%d:%d: %s", path, pos.Line, pos.Column, syntaxErr.Message)
		}
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}

	var version struct {
		Swagger string `yaml:"swagger"`
	}
	if err := yaml.Unmarshal(data, &version); err == nil && version.Swagger != "" {
		return nil, nil, fmt.Errorf("%s: Swagger 2.0 is not supported yet; convert it to OpenAPI 3 (support is tracked in issue #13)", path)
	}

	files := newSpecFiles(path, opts.RefRoot, data)
	defer files.close()
	loader := openapi3.NewLoader()
	loader.IncludeOrigin = true
	loader.ReadFromURIFunc = files.read
	doc, err := loader.LoadFromDataWithPath(withLocations(data), specURL(path))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	// Wrong examples and defaults are documentation mistakes, not security
	// problems, and common in real specs: they must not stop a lint.
	err = doc.Validate(context.Background(),
		openapi3.EnableMultiError(),
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation())
	// A requirement naming an undefined scheme is a security finding
	// (PRC002), with a location and a fix, not a reason to refuse the spec.
	if err = withoutUndefinedSchemes(err); err != nil {
		// Some validation errors append the schema and value on extra lines;
		// the first line says what is wrong.
		msg, _, _ := strings.Cut(err.Error(), "\n")
		return nil, nil, fmt.Errorf("%s: invalid spec: %s", path, msg)
	}
	if err := checkExtensions(doc, files.asGiven); err != nil {
		return nil, nil, err
	}
	return doc, files, nil
}

// splitLines splits a file into lines without their line endings, LF or
// CRLF, so excerpts look the same for specs written on any system.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// readSpec reads the spec, which must be a regular file (not a symlink to
// somewhere else, nor a device that never ends) of at most maxSpecSize.
func readSpec(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: file not found", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPath(err))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (a symlink, directory or device); give the spec file itself", path)
	}
	if leavesWorkingDir(path) {
		return nil, fmt.Errorf("%s: reached through a link leading outside the working directory; give the spec's real path", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPath(err))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSpecSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(data)) > maxSpecSize {
		return nil, fmt.Errorf("%s: larger than %d MiB", path, maxSpecSize>>20)
	}
	return data, nil
}

// unwrapPath drops the operation and path that os errors repeat, since the
// message already starts with the path.
func unwrapPath(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// leavesWorkingDir reports whether a spec written inside the working
// directory really lives outside it, through a directory symlink: a pull
// request could commit such a link to make Procyon read, and root $refs
// in, a directory nobody reviews.
func leavesWorkingDir(path string) bool {
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return false
	}
	if _, inside := within(wd, dir); !inside {
		return false
	}
	_, stillInside := within(evalSymlinks(wd), evalSymlinks(dir))
	return !stillInside
}

// withoutUndefinedSchemes removes kin-openapi's "undefined security scheme"
// errors that PRC002 reports from a validation error, returning nil when
// nothing else is left.
func withoutUndefinedSchemes(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case *openapi3.SecurityRequirementSchemeUndefinedError:
		if coveredByPRC002(e.JSONPointer) {
			return nil
		}
		return err
	case openapi3.MultiError:
		var kept openapi3.MultiError
		for _, inner := range e {
			if inner = withoutUndefinedSchemes(inner); inner != nil {
				kept = append(kept, inner)
			}
		}
		switch len(kept) {
		case 0:
			return nil
		case 1:
			return kept[0]
		}
		return kept
	}
	// A context wrapper ("invalid path /orders: ...") around nothing but
	// undefined schemes goes too.
	if inner := errors.Unwrap(err); inner != nil && withoutUndefinedSchemes(inner) == nil {
		return nil
	}
	return err
}

// coveredByPRC002 reports whether PRC002 checks the requirement at pointer:
// the global one and those of path operations. Webhooks and callbacks are
// not checked, so their undefined schemes must stay errors rather than
// vanish.
func coveredByPRC002(pointer string) bool {
	return strings.HasPrefix(pointer, "/security/") ||
		(strings.HasPrefix(pointer, "/paths/") && !strings.Contains(pointer, "/callbacks/"))
}
