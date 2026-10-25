package main_test

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

var notesSpec = filepath.Join("..", "..", "internal", "vulnapi", "openapi.yaml")

func TestTestCommandExitCodes(t *testing.T) {
	vulnerable := httptest.NewServer(vulnapi.New(false))
	defer vulnerable.Close()
	fixed := httptest.NewServer(vulnapi.New(true))
	defer fixed.Close()

	tests := []struct {
		name   string
		args   []string
		code   int
		output string // substring of stdout or stderr
	}{
		{"finding fails the run", []string{"--base-url", vulnerable.URL, notesSpec}, 1, "PRC101"},
		{"fixed API passes", []string{"--base-url", fixed.URL, notesSpec}, 0, "PASSED"},
		{"lower threshold than the finding", []string{"--fail-on", "critical", "--base-url", fixed.URL, notesSpec}, 0, "PASSED"},
		{"base URL is required", []string{notesSpec}, 2, "--base-url is required"},
		{"public target is refused", []string{"--base-url", "http://8.8.8.8", notesSpec}, 2, "not a loopback or private address"},
		{"lint flags work", []string{"--format", "json", "--base-url", vulnerable.URL, notesSpec}, 1, `"version": 1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, append([]string{"test"}, tt.args...)...)
			if r.code != tt.code {
				t.Errorf("exit code = %d, want %d; stderr: %s", r.code, tt.code, r.stderr)
			}
			if !strings.Contains(r.stdout+r.stderr, tt.output) {
				t.Errorf("output does not contain %q:\n%s%s", tt.output, r.stdout, r.stderr)
			}
		})
	}
}
