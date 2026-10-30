package lint_test

import (
	"path/filepath"
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
		"valid-conflicting-paths.yaml",   // /users/{id} and /users/{name}: invalid OpenAPI, not a security problem
		"valid-unsupported-pattern.yaml", // a lookahead Go cannot compile, a [ in a schema name (AWS, Azure)
		"swagger-2.0.yaml",
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
		{"public operation without a reason", "public-empty-reason.yaml", []string{"public-empty-reason.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
		{"public operation marked with a boolean", "public-not-a-string.yaml", []string{"public-not-a-string.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
		{"remote $ref", "ref-remote.yaml", []string{"ref-remote.yaml", "https://example.com/orders.yaml", "never fetches"}},
		{"missing local $ref", "ref-missing.yaml", []string{"ref-missing.yaml", "missing.yaml"}},
		{"$ref escaping the working directory", "ref-escapes.yaml", []string{"ref-escapes.yaml", "outside"}},
		{"undefined scheme does not hide another error", "invalid-spec-and-undefined-scheme.yaml", []string{"invalid-spec-and-undefined-scheme.yaml", "info"}},
		// PRC002 does not look into webhooks or callbacks, so an undefined
		// scheme there must still stop the run instead of passing silently.
		{"undefined scheme in a webhook", "invalid-undefined-scheme-in-webhook.yaml", []string{"undefined security scheme", "missing"}},
		{"undefined scheme in a callback", "invalid-undefined-scheme-in-callback.yaml", []string{"undefined security scheme", "missing"}},
		// A typo in an ignore must never silently ignore something.
		{"ignore without a reason", "ignore-no-reason.yaml", []string{"ignore-no-reason.yaml:8:7:", "GET /health", "reason"}},
		{"ignore of an unknown rule", "ignore-unknown-rule.yaml", []string{"ignore-unknown-rule.yaml:8:7:", "PRC01"}},
		{"ignore with a malformed date", "ignore-bad-date.yaml", []string{"ignore-bad-date.yaml:8:7:", "expires", "tomorrow"}},
		{"ignore that is not a list", "ignore-not-a-list.yaml", []string{"ignore-not-a-list.yaml:8:7:", "list"}},
		{"Swagger 2.0 with a null path item", "swagger-2.0-null.yaml", []string{"swagger-2.0-null.yaml:6:3:", "/u"}},
		{"Swagger 2.0 path item $ref", "swagger-2.0-pathref.yaml", []string{"swagger-2.0-pathref.yaml", "/users", "$ref"}},
		{"Swagger 2.0 YAML alias bomb of long strings", "swagger-2.0-string-bomb.yaml", []string{"swagger-2.0-string-bomb.yaml", "alias"}},
		{"Swagger 2.0 with a null default response", "swagger-2.0-null-default.yaml", []string{"swagger-2.0-null-default.yaml:9:9:", "default"}},
		{"Swagger 2.0 with a list where a schema must be", "swagger-2.0-tuple.yaml", []string{"swagger-2.0-tuple.yaml:13:13:", "items", "list"}},
		{"Swagger 2.0 YAML alias bomb", "swagger-2.0-alias-bomb.yaml", []string{"swagger-2.0-alias-bomb.yaml", "alias"}},
		{"Swagger 2.0 split across files", "swagger-2.0-split.yaml", []string{"swagger-2.0-split.yaml", "./definitions.yaml#/User", "one file"}},
		{"public marker error keeps the path as written", "dir with space/public-empty-reason.yaml", []string{"dir with space/public-empty-reason.yaml:7:5:"}},
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

func TestRunKeepsSourceLinesWithoutCarriageReturns(t *testing.T) {
	rep, err := lint.Run(spec("crlf.yaml"), lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lines := rep.Sources[spec("crlf.yaml")]
	if len(lines) != 10 {
		t.Fatalf("got %d source lines, want 10", len(lines))
	}
	if got, want := lines[6], "    get:"; got != want {
		t.Errorf("line 7 = %q, want %q", got, want)
	}
}

// kin-openapi records each element's file as a URL ("dir%20with%20space",
// "%5C" for Windows backslashes). Findings must use the path as the user
// wrote it, and it must be the key of the report's source lines.
func TestFindingsUseThePathAsGiven(t *testing.T) {
	path := spec("dir with space/no-auth.yaml")
	rep, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	if got := rep.Findings[0].Location.File; got != path {
		t.Errorf("finding file = %q, want %q", got, path)
	}
	if _, ok := rep.Sources[rep.Findings[0].Location.File]; !ok {
		t.Errorf("no source lines for %q", rep.Findings[0].Location.File)
	}
}

func TestSpecsSplitAcrossLocalFiles(t *testing.T) {
	path := spec("split/api.yaml")
	rep, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (PRC001 on GET /orders)", len(rep.Findings))
	}
	f := rep.Findings[0]
	// The operation is written in paths/orders.yaml, line 1, column 1.
	want := filepath.Clean(spec("split/paths/orders.yaml")) // \ on Windows, like the location
	if f.Location.File != want || f.Location.Line != 1 || f.Location.Column != 1 {
		t.Errorf("location = %s:%d:%d, want %s:1:1", f.Location.File, f.Location.Line, f.Location.Column, want)
	}
	if _, ok := rep.Sources[want]; !ok {
		t.Errorf("no source lines for %s, so no excerpt", want)
	}
}
