// Package lint checks a spec for security problems in the API's design.
package lint

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
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
	// Today decides whether an ignore has expired. Zero means now.
	Today time.Time
}

// Run lints the spec at path.
func Run(path string, opts Options) (Report, error) {
	doc, data, err := load(path)
	if err != nil {
		return Report{}, err
	}
	// kin-openapi records each element's file as a URL: spaces become %20,
	// Windows backslashes %5C. Findings use the path as the user wrote it.
	files := map[string]string{specURL(path).String(): path}
	report := Report{
		FailOn:  opts.FailOn,
		Sources: map[string][]string{path: splitLines(data)},
	}
	if report.FailOn == 0 {
		report.FailOn = High
	}
	// asGiven turns kin-openapi's file URL back into the path read.
	asGiven := func(loc Location) Location {
		if given, ok := files[loc.File]; ok {
			loc.File = given
		}
		return loc
	}
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
func load(path string) (*openapi3.T, []byte, error) {
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

	loader := openapi3.NewLoader()
	loader.IncludeOrigin = true
	// kin-openapi records locations only on its YAML path, and it tries JSON
	// first. A trailing YAML comment makes the JSON attempt fail while the
	// file stays valid YAML (JSON is YAML) with every line and column
	// unchanged, so JSON specs get locations too.
	doc, err := loader.LoadFromDataWithPath(append(data, "\n# procyon\n"...), specURL(path))
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
	if err := checkExtensions(doc); err != nil {
		return nil, nil, err
	}
	return doc, data, nil
}

// splitLines splits a file into lines without their line endings, LF or
// CRLF, so excerpts look the same for specs written on any system.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// specURL is the location kin-openapi is given for the spec at path, and so
// the one its origins report.
func specURL(path string) *url.URL {
	return &url.URL{Path: path}
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
