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
		{"public operation without a reason", "public-empty-reason.yaml", []string{"public-empty-reason.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
		{"public operation marked with a boolean", "public-not-a-string.yaml", []string{"public-not-a-string.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
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

func TestRunKeepsSourceLinesWithoutCarriageReturns(t *testing.T) {
	report, err := lint.Run(spec("crlf.yaml"), lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lines := report.Sources[spec("crlf.yaml")]
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
	report, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(report.Findings))
	}
	if got := report.Findings[0].Location.File; got != path {
		t.Errorf("finding file = %q, want %q", got, path)
	}
	if _, ok := report.Sources[report.Findings[0].Location.File]; !ok {
		t.Errorf("no source lines for %q", report.Findings[0].Location.File)
	}
}
