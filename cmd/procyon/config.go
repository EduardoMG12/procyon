package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/EduardoMG12/procyon/internal/lint"
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

	outputs outputs // Output, parsed
}

// positionedError is implemented by goccy/go-yaml's syntax and decoding
// errors.
type positionedError interface {
	GetToken() *token.Token
	GetMessage() string
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
	for _, value := range cfg.Output {
		o, err := parseOutput(value)
		if err != nil {
			return cfg, fmt.Errorf("%s: output: %w", configFile, err)
		}
		cfg.outputs = append(cfg.outputs, o)
	}
	return cfg, nil
}
