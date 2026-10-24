// Package lint checks a spec for security problems in the API's design.
package lint

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// Options control a run.
type Options struct {
	// RefRoot is the directory $refs may read files from. Empty means the
	// spec's own directory. A monorepo whose specs share files from a
	// sibling folder sets it to the repository root. It must contain the
	// spec, and it may not be the file system's root or the home directory.
	RefRoot string
}

// Run lints the spec at path.
func Run(path string, opts Options) (Report, error) {
	doc, files, err := load(path, opts)
	if err != nil {
		return Report{}, err
	}
	report := Report{FailOn: High, Sources: files.lines}
	for _, rule := range rules {
		for _, f := range rule.check(doc) {
			f.Rule = rule
			// kin-openapi records files as URLs; findings use the path read.
			if given, ok := files.paths[f.Location.File]; ok {
				f.Location.File = given
			}
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
	if info, err := os.Stat(path); err == nil && info.Size() > maxSpecSize {
		return nil, nil, fmt.Errorf("%s: larger than %d MiB", path, maxSpecSize>>20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%s: file not found", path)
		}
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return nil, nil, fmt.Errorf("%s: %w", path, err)
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
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation())
	if err != nil {
		// Some validation errors append the schema and value on extra lines;
		// the first line says what is wrong.
		msg, _, _ := strings.Cut(err.Error(), "\n")
		return nil, nil, fmt.Errorf("%s: invalid spec: %s", path, msg)
	}
	return doc, files, nil
}

// splitLines splits a file into lines without their line endings, LF or
// CRLF, so excerpts look the same for specs written on any system.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}
