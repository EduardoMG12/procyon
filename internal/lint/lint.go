// Package lint checks a spec for security problems in the API's design.
package lint

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// Options control a run.
type Options struct{}

// Report is everything one run produced.
type Report struct{}

// Run lints the spec at path.
func Run(path string, opts Options) (Report, error) {
	if _, err := load(path); err != nil {
		return Report{}, err
	}
	return Report{}, nil
}

// load reads the spec at path, recording the file, line and column of every
// element so findings can point at the original file.
func load(path string) (*openapi3.T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: file not found", path)
		}
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	// kin-openapi's own syntax errors are off by a line for some YAML
	// mistakes and mix a JSON and a YAML message. goccy/go-yaml reports the
	// exact line and column, and reads JSON too (JSON is valid YAML).
	if _, err := parser.ParseBytes(data, 0); err != nil {
		var syntaxErr *yaml.SyntaxError
		if errors.As(err, &syntaxErr) && syntaxErr.Token != nil {
			pos := syntaxErr.Token.Position
			return nil, fmt.Errorf("%s:%d:%d: %s", path, pos.Line, pos.Column, syntaxErr.Message)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	var version struct {
		Swagger string `yaml:"swagger"`
	}
	if err := yaml.Unmarshal(data, &version); err == nil && version.Swagger != "" {
		return nil, fmt.Errorf("%s: Swagger 2.0 is not supported yet; convert it to OpenAPI 3 (support is tracked in issue #13)", path)
	}

	loader := openapi3.NewLoader()
	loader.IncludeOrigin = true
	doc, err := loader.LoadFromDataWithPath(data, &url.URL{Path: path})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
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
		return nil, fmt.Errorf("%s: invalid spec: %s", path, msg)
	}
	return doc, nil
}
