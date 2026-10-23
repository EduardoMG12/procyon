package lint_test

import (
	"os"
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
		{"remote $ref", "ref-remote.yaml", []string{"ref-remote.yaml", "https://example.com/orders.yaml", "never fetches"}},
		{"missing local $ref", "ref-missing.yaml", []string{"ref-missing.yaml", "missing.yaml"}},
		{"$ref escaping the working directory", "ref-escapes.yaml", []string{"ref-escapes.yaml", "outside"}},
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

func TestSpecsSplitAcrossLocalFiles(t *testing.T) {
	path := spec("split/api.yaml")
	report, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (PRC001 on GET /orders)", len(report.Findings))
	}
	f := report.Findings[0]
	// The operation is written in paths/orders.yaml, line 1, column 1.
	want := spec("split/paths/orders.yaml")
	if f.Location.File != want || f.Location.Line != 1 || f.Location.Column != 1 {
		t.Errorf("location = %s:%d:%d, want %s:1:1", f.Location.File, f.Location.Line, f.Location.Column, want)
	}
	if _, ok := report.Sources[want]; !ok {
		t.Errorf("no source lines for %s, so no excerpt", want)
	}
}

// A symlink inside the spec's directory must not become a way out of it.
func TestRefThroughSymlinkCannotLeaveTheSpecDirectory(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(secret, []byte("get:\n  responses: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "orders.yaml")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	spec := filepath.Join(dir, "api.yaml")
	body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"./orders.yaml\"\n"
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Run = %v, want an error saying the $ref points outside", err)
	}
}

// The attack found in review: an absolute $ref through a committed symlink
// and "..", where the path checked and the path read used to differ.
func TestRefCannotEscapeWithAbsolutePathThroughSymlink(t *testing.T) {
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	stolen := "get:\n  description: STOLEN\n  responses:\n    \"200\":\n      description: OK\n"
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte(stolen), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	// A harmless decoy where the cleaned path points, so a check on the
	// cleaned path passes while a read of the raw path follows the link.
	decoy := "get:\n  responses:\n    \"200\":\n      description: OK\n"
	if err := os.WriteFile(filepath.Join(dir, "secret.yaml"), []byte(decoy), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := filepath.ToSlash(filepath.Join(dir, "link")) + "/../secret.yaml"
	spec := filepath.Join(dir, "api.yaml")
	body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"" + ref + "\"\n"
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := lint.Run(spec, lint.Options{})
	for _, lines := range report.Sources {
		if strings.Contains(strings.Join(lines, "\n"), "STOLEN") {
			t.Fatal("Procyon read a file outside the spec's directory")
		}
	}
	if err == nil && len(report.Findings) > 0 {
		// Reading the decoy inside the directory is fine; the stolen file is not.
		t.Logf("read the decoy: %s", report.Findings[0].Location.File)
	}
}

// A $ref to an absolute path outside the allowed directories is refused
// without touching the file system: same message whether the file exists or
// not, so a spec cannot probe the machine running Procyon.
func TestRefOutsideGivesTheSameErrorWhetherOrNotTheFileExists(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "exists.yaml")
	if err := os.WriteFile(existing, []byte("get: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	var messages []string
	for _, target := range []string{existing, missing} {
		dir := t.TempDir()
		spec := filepath.Join(dir, "api.yaml")
		body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"" + filepath.ToSlash(target) + "\"\n"
		if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := lint.Run(spec, lint.Options{})
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("Run = %v, want an error saying the $ref points outside", err)
		}
		messages = append(messages, strings.ReplaceAll(err.Error(), filepath.ToSlash(target), "TARGET"))
	}
	for i := range messages {
		messages[i] = messages[i][strings.Index(messages[i], "$ref"):]
	}
	if messages[0] != messages[1] {
		t.Errorf("messages differ, revealing whether the file exists:\n %s\n %s", messages[0], messages[1])
	}
}
