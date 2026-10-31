// Package loader reads a spec (OpenAPI 3.0, 3.1 or Swagger 2.0, in YAML
// or JSON, split across local files or not) with the file, line and column
// of every element, refuses what it must not read, and answers the
// questions lint rules and runtime tests both ask about it: its
// operations, their security, their parameters, its ignores.
package loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Options control how a spec is loaded.
type Options struct {
	// RefRoot is the directory $refs may read files from. Empty means the
	// spec's own directory. A monorepo whose specs share files from a
	// sibling folder sets it to the repository root. It must contain the
	// spec, and it may not be the file system's root or the home directory.
	RefRoot string
	// KnownRule reports whether a rule ID exists, so an x-procyon-ignore of
	// a misspelled rule is an error. The rules live in internal/lint.
	KnownRule func(id string) bool
}

// load reads the spec at path, recording the file, line and column of every
// element so findings can point at the original file.
func load(path string, opts Options) (*openapi3.T, *specFiles, error) {
	data, err := readSpec(path)
	if err != nil {
		return nil, nil, err
	}
	// Valid JSON needs no YAML syntax check, which takes seconds on a large
	// spec. If anything fails later, the check runs after all, so the error
	// a user sees is the same with or without this shortcut (goccy refuses
	// duplicate keys, which encoding/json accepts).
	if json.Valid(data) {
		doc, files, err := loadParsed(path, opts, data, nil, jsonSwaggerVersion(data))
		if err != nil {
			if _, syntaxErr := checkSyntax(path, data); syntaxErr != nil {
				return nil, nil, syntaxErr
			}
		}
		return doc, files, err
	}
	file, err := checkSyntax(path, data)
	if goccyKeepBug(err) {
		// kin-openapi parses with its own YAML parser, which reads such a
		// block: if it loads the spec, lint it without goccy's syntax tree,
		// as JSON is; if not, goccy's error stands. A Swagger 2.0 spec stays
		// refused: it needs the tree to be converted, and loaded as OpenAPI
		// 3 it has no openapi version.
		if doc, files, loadErr := loadParsed(path, opts, data, nil, nil); loadErr == nil {
			return doc, files, nil
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return loadParsed(path, opts, data, file, swaggerVersion(file))
}

// goccyKeepBug reports whether err is goccy/go-yaml refusing valid YAML: a
// block scalar that keeps its line breaks (|+ or >+) but has no content,
// such as "example: |+" followed by a blank line in DigitalOcean's spec.
// goccy/go-yaml v1.19.2, the latest release, has the bug.
//
// ponytail: matches goccy's message, so if a release rewords it such specs
// are refused again (never wrongly accepted); drop this once goccy fixes it.
func goccyKeepBug(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ": could not find multi-line content")
}

// checkSyntax parses the spec as YAML. kin-openapi's own syntax errors are
// off by a line for some YAML mistakes and mix a JSON and a YAML message.
// goccy/go-yaml reports the exact line and column, and reads JSON too (JSON
// is valid YAML).
func checkSyntax(path string, data []byte) (*ast.File, error) {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		var syntaxErr *yaml.SyntaxError
		if errors.As(err, &syntaxErr) && syntaxErr.Token != nil {
			pos := syntaxErr.Token.Position
			return nil, fmt.Errorf("%s:%d:%d: %s", path, pos.Line, pos.Column, syntaxErr.Message)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return file, nil
}

// jsonSwaggerVersion is swaggerVersion for a JSON spec.
func jsonSwaggerVersion(data []byte) any {
	var version struct {
		Swagger any `json:"swagger"` // a string, or a number when 2.0 is unquoted
	}
	if json.Unmarshal(data, &version) != nil {
		return nil
	}
	return version.Swagger
}

// loadParsed loads a spec whose syntax is known to be right; file is its
// syntax tree, or nil for JSON, and swagger its top-level swagger value, or
// nil for OpenAPI 3.
func loadParsed(path string, opts Options, data []byte, file *ast.File, swagger any) (*openapi3.T, *specFiles, error) {
	var err error
	// Swagger 2.0 is converted to OpenAPI 3 and linted like any spec;
	// locations are mapped back to the original file (see fromSwagger).
	toLoad := data
	var back func(position) (position, bool)
	if swagger != nil {
		if v := fmt.Sprint(swagger); v != "2" && !strings.HasPrefix(v, "2.") {
			return nil, nil, fmt.Errorf("%s: swagger %q is not a version Procyon knows; use Swagger 2.0 or OpenAPI 3", path, v)
		}
		if toLoad, back, err = fromSwagger(data, file); err != nil {
			if placed, ok := errors.AsType[*positionError](err); ok && placed.at.line > 0 {
				return nil, nil, fmt.Errorf("%s:%w", path, err) // file:line:col: message
			}
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}

	files := newSpecFiles(path, opts.RefRoot, data) // excerpts show the original
	files.back = back
	defer files.close()
	loader := openapi3.NewLoader()
	loader.IncludeOrigin = true
	loader.ReadFromURIFunc = files.read
	doc, err := loader.LoadFromDataWithPath(files.withLocations(path, toLoad), specURL(path))
	if files.overLimit != nil {
		err = files.overLimit // see specFiles.overLimit
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	// kin-openapi validates a version it does not list (3.3.0, 4.0.0, a
	// 3.1 patch newer than it) by 3.0's rules: refuse it by name instead.
	if v := doc.OpenAPI; v != "" && doc.OpenAPIMajorMinor() == "" {
		return nil, nil, fmt.Errorf("%s: openapi %q is not a version Procyon knows; use OpenAPI 3.0, 3.1 or 3.2, or Swagger 2.0", path, v)
	}
	if doc.IsOpenAPI31OrLater() {
		dropUnknownKeywords(doc)
	}
	// Wrong examples, defaults and patterns are documentation mistakes, not security
	// problems, and common in real specs: they must not stop a lint.
	err = doc.Validate(context.Background(),
		openapi3.EnableMultiError(),
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaPatternValidation(), // Go's regexp lacks lookaheads (AWS specs use them)
		openapi3.DisableSchemaDefaultsValidation())
	// A requirement naming an undefined scheme is a security finding
	// (PRC002), with a location and a fix, not a reason to refuse the spec.
	if err = withoutTolerated(err); err != nil {
		// A hint, not a diagnosis: the unknown field may also be a typo.
		hint := ""
		if _, unknownField := errors.AsType[*openapi3.ExtraSiblingFieldsError](err); unknownField && doc.IsOpenAPI32OrLater() {
			hint = " (OpenAPI 3.2 is only partly supported: some fields new in 3.2, such as a tag's kind, are refused)"
		}
		return nil, nil, invalidSpec(path, err, hint, files.asGiven)
	}
	if err := checkExtensions(doc, files.asGiven); err != nil {
		return nil, nil, err
	}
	return doc, files, nil
}

// swaggerVersion is the value of the document's top-level swagger key (a
// string, or a number when 2.0 is unquoted), or nil when there is none. It
// reads it from the syntax tree the syntax check already built: decoding
// the whole document only for this key cost seconds on large specs.
func swaggerVersion(file *ast.File) any {
	if len(file.Docs) == 0 {
		return nil
	}
	var pairs []*ast.MappingValueNode
	switch body := file.Docs[0].Body.(type) {
	case *ast.MappingNode:
		pairs = body.Values
	case *ast.MappingValueNode:
		pairs = []*ast.MappingValueNode{body}
	}
	for _, pair := range pairs {
		key := pair.Key.String()
		if str, quoted := pair.Key.(*ast.StringNode); quoted {
			key = str.Value // "swagger" in JSON, without its quotes
		}
		if key != "swagger" {
			continue
		}
		var v any
		if yaml.NodeToValue(pair.Value, &v) != nil {
			return nil
		}
		return v
	}
	return nil
}

// splitLines splits a file into lines without their line endings, LF or
// CRLF, so excerpts look the same for specs written on any system.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// withoutTolerated removes from a validation error what must not stop a
// lint, returning nil when nothing else is left: the "undefined security
// scheme" errors PRC002 reports, and mistakes OpenAPI forbids but that say
// nothing about security and are common in large real specs: conflicting
// paths (/users/{id} and /users/{name}, GitHub's spec) and component names
// outside OpenAPI 3's charset (Order[Draft], Azure's Swagger 2.0 specs).
func withoutTolerated(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case *openapi3.ConflictingPathsError:
		return nil
	case *openapi3.ComponentValidationError:
		if bad := openapi3.ValidateIdentifier(e.Name); bad != nil && e.Cause != nil && e.Cause.Error() == bad.Error() {
			return nil // the name is the only problem: kin skips the rest of that component
		}
		return err
	case *openapi3.SecurityRequirementSchemeUndefinedError:
		if coveredByPRC002(e.JSONPointer) {
			return nil
		}
		return err
	case openapi3.MultiError:
		var kept openapi3.MultiError
		for _, inner := range e {
			if inner = withoutTolerated(inner); inner != nil {
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
	// tolerated errors goes too.
	if inner := errors.Unwrap(err); inner != nil && withoutTolerated(inner) == nil {
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
