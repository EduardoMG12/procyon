package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/test"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/token"
)

// configFile is read from the working directory when it exists. It holds
// how Procyon runs, never what it ignores: ignores live in the spec, next to
// the operation they excuse.
const configFile = ".procyon.yaml"

type config struct {
	FailOn  string   `yaml:"fail-on"`
	RefRoot string   `yaml:"ref-root"`
	Format  string   `yaml:"format"`
	Output  []string `yaml:"output"` // format=path, like --output
	Test    struct {
		// IDs are values of test account A's objects by path parameter
		// name, for objects A's responses never show.
		IDs map[string][]string `yaml:"ids"`
		// Skip lists operations never called ("GET /createdb").
		Skip []string `yaml:"skip"`
		// Accounts declare how test accounts A and B log in.
		Accounts struct {
			A struct {
				Login *test.Login `yaml:"login"`
			} `yaml:"a"`
			B struct {
				Login *test.Login `yaml:"login"`
			} `yaml:"b"`
		} `yaml:"accounts"`
	} `yaml:"test"`

	outputs outputs // Output, parsed
}

// positionedError is implemented by goccy/go-yaml's syntax and decoding
// errors.
type positionedError interface {
	GetToken() *token.Token
	GetMessage() string
}

// positionOf is "file:line:column" of the YAML node at path ($.test.x),
// or the file name alone when it cannot be found.
func positionOf(data []byte, path string) string {
	p, err := yaml.PathString(path)
	if err != nil {
		return configFile
	}
	node, err := p.ReadNode(bytes.NewReader(data))
	if err != nil || node == nil || node.GetToken() == nil {
		return configFile
	}
	pos := node.GetToken().Position
	return fmt.Sprintf("%s:%d:%d", configFile, pos.Line, pos.Column)
}

// loadConfig returns the zero config when there is no file.
func loadConfig() (config, error) {
	var cfg config
	data, err := os.ReadFile(configFile)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", configFile, err)
	}
	// A typo such as fail_on must be an error, not silently ignored.
	if err := yaml.UnmarshalWithOptions(data, &cfg, yaml.DisallowUnknownField()); err != nil {
		var posErr positionedError
		if errors.As(err, &posErr) && posErr.GetToken() != nil {
			pos := posErr.GetToken().Position
			return cfg, fmt.Errorf("%s:%d:%d: %s", configFile, pos.Line, pos.Column, posErr.GetMessage())
		}
		return cfg, fmt.Errorf("%s: %w", configFile, err)
	}
	if cfg.FailOn != "" {
		if _, err := lint.ParseSeverity(cfg.FailOn); err != nil {
			return cfg, fmt.Errorf("%s: fail-on: %w", configFile, err)
		}
	}
	if cfg.Format != "" && formats[cfg.Format] == nil {
		return cfg, fmt.Errorf("%s: format: unknown format %q (use %s)", configFile, cfg.Format, formatNames())
	}
	for _, account := range []struct {
		name  string
		login *test.Login
	}{{"a", cfg.Test.Accounts.A.Login}, {"b", cfg.Test.Accounts.B.Login}} {
		if l := account.login; l != nil && (l.Operation == "" || l.Token == "") {
			key := "test.accounts." + account.name + ".login"
			return cfg, fmt.Errorf("%s: %s needs operation (\"POST /login\") and token (a JSON pointer such as /token)",
				positionOf(data, "$."+key), key)
		}
	}
	for _, value := range cfg.Output {
		o, err := parseOutput(value)
		if err != nil {
			return cfg, fmt.Errorf("%s: output: %w", configFile, err)
		}
		cfg.outputs = append(cfg.outputs, o)
	}
	return cfg, nil
}
