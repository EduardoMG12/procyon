package lint_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// TestRules pins exactly which findings of the rules under test each
// fixture spec produces, and where. Findings of other rules are ignored, so
// adding a rule never breaks another rule's fixtures; a row that cares
// about two rules interacting lists both. Expected locations are counted by
// hand in the fixture, never computed.
func TestRules(t *testing.T) {
	tests := []struct {
		spec  string
		rules []string // the rules under test
		want  []string // "RULE file:line:column METHOD /path"
	}{
		{"prc001-no-auth.yaml", []string{"PRC001"}, []string{
			"PRC001 prc001-no-auth.yaml:7:5 GET /orders",
		}},
		{"prc001-no-auth.json", []string{"PRC001"}, []string{
			"PRC001 prc001-no-auth.json:6:7 GET /orders",
		}},
		{"prc001-no-auth-tabs.json", []string{"PRC001"}, []string{
			"PRC001 prc001-no-auth-tabs.json:9:4 GET /orders",
		}},
		{"prc001-global-security.yaml", []string{"PRC001"}, []string{}},
		{"prc008-limits.yaml", []string{"PRC008"}, []string{
			"PRC008 prc008-limits.yaml:9:5 GET /orders",
			"PRC008 prc008-limits.yaml:26:17 POST /orders",
			"PRC008 prc008-limits.yaml:40:17 POST /orders",
			"PRC008 prc008-limits.yaml:51:23 POST /orders",
		}},
		{"prc009-mass-assignment.yaml", []string{"PRC009"}, []string{
			"PRC009 prc009-mass-assignment.yaml:34:17 PATCH /users/{id}",
			"PRC009 prc009-mass-assignment.yaml:81:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:83:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:85:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:89:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:93:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:105:13 POST /users",
			"PRC009 prc009-mass-assignment.yaml:107:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:111:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:115:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:117:9 POST /users",
		}},
		{"prc005-secrets.yaml", []string{"PRC005"}, []string{
			"PRC005 prc005-secrets.yaml:39:25 GET /sessions",
			"PRC005 prc005-secrets.yaml:70:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:72:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:74:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:76:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:78:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:88:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:94:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:96:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:98:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:102:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:106:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:108:9 GET /sessions",
			"PRC005 prc005-secrets.yaml:115:13 GET /sessions",
		}},
		{"prc005-nullable-boolean-3.1.yaml", []string{"PRC005"}, []string{}},
		{"prc001-empty-override.yaml", []string{"PRC001"}, []string{
			"PRC001 prc001-empty-override.yaml:13:5 DELETE /orders",
		}},
		{"prc001-optional-auth.yaml", []string{"PRC001"}, []string{
			"PRC001 prc001-optional-auth.yaml:7:5 GET /orders",
		}},
		{"prc001-file-order.yaml", []string{"PRC001"}, []string{
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
			got := summarize(report.Findings, tt.rules)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings:\n got  %q\n want %q", got, tt.want)
			}
		})
	}
}

func summarize(findings []lint.Finding, rules []string) []string {
	out := []string{}
	for _, f := range findings {
		if !slices.Contains(rules, f.Rule.ID) {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s:%d:%d %s",
			f.Rule.ID, filepath.Base(f.Location.File), f.Location.Line, f.Location.Column, f.Operation))
	}
	return out
}
