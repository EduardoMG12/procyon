package lint_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// TestRules pins exactly which findings each fixture spec produces, and where.
// Expected locations are counted by hand in the fixture, never computed.
func TestRules(t *testing.T) {
	tests := []struct {
		spec string
		want []string // "RULE file:line:column METHOD /path"
	}{
		{"prc001-no-auth.yaml", []string{
			"PRC001 prc001-no-auth.yaml:7:5 GET /orders",
		}},
		{"prc001-no-auth.json", []string{
			"PRC001 prc001-no-auth.json:6:7 GET /orders",
		}},
		{"prc001-no-auth-tabs.json", []string{
			"PRC001 prc001-no-auth-tabs.json:9:4 GET /orders",
		}},
		{"prc001-global-security.yaml", []string{}},
		// /admin/users inherits the default: reported. /admin/orders has
		// its own scope: not. /internal/metrics repeats the default: reported.
		// /debug-tools has "debug" as a word: reported. /administrators-guide
		// is not "admin". /management has no auth at all: PRC001, not PRC010.
		{"prc010-admin.yaml", []string{
			"PRC010 prc010-admin.yaml:9:5 GET /admin/users",
			"PRC010 prc010-admin.yaml:21:5 GET /internal/metrics",
			"PRC010 prc010-admin.yaml:28:5 DELETE /debug-tools/cache",
			"PRC001 prc010-admin.yaml:38:5 GET /management",
		}},
		{"prc001-empty-override.yaml", []string{
			"PRC001 prc001-empty-override.yaml:13:5 DELETE /orders",
		}},
		{"prc001-optional-auth.yaml", []string{
			"PRC001 prc001-optional-auth.yaml:7:5 GET /orders",
		}},
		{"prc001-file-order.yaml", []string{
			"PRC001 prc001-file-order.yaml:7:5 GET /zebras",
			"PRC001 prc001-file-order.yaml:12:5 GET /apples",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			report, err := lint.Run(spec(tt.spec), lint.Options{})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := summarize(report.Findings)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings:\n got  %q\n want %q", got, tt.want)
			}
		})
	}
}

func summarize(findings []lint.Finding) []string {
	out := []string{}
	for _, f := range findings {
		out = append(out, fmt.Sprintf("%s %s:%d:%d %s",
			f.Rule.ID, filepath.Base(f.Location.File), f.Location.Line, f.Location.Column, f.Operation))
	}
	return out
}
