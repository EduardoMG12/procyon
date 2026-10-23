package lint_test

import (
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
)

func TestRunAcceptsValidSpecs(t *testing.T) {
	specs := []string{
		"valid-3.0.yaml",
		"valid-3.1.yaml",
		"valid-3.0.json",
		"valid-3.1.json",
		"valid-wrong-example.yaml", // examples and defaults are not security: never block a lint
		"valid-wrong-default.yaml",
	}
	for _, name := range specs {
		t.Run(name, func(t *testing.T) {
			if _, err := lint.Run(spec(name), lint.Options{}); err != nil {
				t.Fatalf("Run(%s) returned error: %v", name, err)
			}
		})
	}
}

func spec(name string) string {
	return "../../testdata/specs/" + name
}

func TestRunRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []string // substrings the one-line error must contain
	}{
		{"missing file", "does-not-exist.yaml", []string{"does-not-exist.yaml"}},
		{"invalid YAML", "invalid-yaml.yaml", []string{"invalid-yaml.yaml:7:10:"}},
		{"invalid JSON", "invalid-json.json", []string{"invalid-json.json:4:23:"}},
		{"spec without info", "invalid-spec-no-info.yaml", []string{"invalid-spec-no-info.yaml", "info"}},
		{"undefined scheme does not hide another error", "invalid-spec-and-undefined-scheme.yaml", []string{"invalid-spec-and-undefined-scheme.yaml", "info"}},
		// PRC002 does not look into webhooks or callbacks, so an undefined
		// scheme there must still stop the run instead of passing silently.
		{"undefined scheme in a webhook", "invalid-undefined-scheme-in-webhook.yaml", []string{"undefined security scheme", "missing"}},
		{"undefined scheme in a callback", "invalid-undefined-scheme-in-callback.yaml", []string{"undefined security scheme", "missing"}},
		{"Swagger 2.0", "swagger-2.0.yaml", []string{"swagger-2.0.yaml", "Swagger 2.0", "not supported yet"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lint.Run(spec(tt.file), lint.Options{})
			if err == nil {
				t.Fatalf("Run(%s) returned no error", tt.file)
			}
			msg := err.Error()
			if strings.Contains(msg, "\n") {
				t.Errorf("error is not one line: %q", msg)
			}
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not mention %q", msg, w)
				}
			}
		})
	}
}
