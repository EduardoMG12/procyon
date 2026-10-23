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
		{"public-operation.yaml", []string{"PRC001"}, []string{
			"PRC001 public-operation.yaml:13:5 GET /orders",
		}},
		// 2 schemes × 70 regions × 3 versions: more combinations than
		// Procyon expands, and http must still be found, on every run.
		{"prc004-many-values.yaml", []string{"PRC004"}, []string{
			"PRC004 prc004-many-values.yaml:6:5 ",
		}},
		// 40 × 40 scheme values: too many to check, so Procyon fails closed
		// and reports, even though none of them is http.
		{"prc004-too-many-combinations.yaml", []string{"PRC004"}, []string{
			"PRC004 prc004-too-many-combinations.yaml:6:5 ",
		}},
		{"prc004-servers.yaml", []string{"PRC004"}, []string{
			"PRC004 prc004-servers.yaml:6:5 ",
			"PRC004 prc004-servers.yaml:12:5 ",
			"PRC004 prc004-servers.yaml:22:9 ",
			"PRC004 prc004-servers.yaml:25:11 GET /orders",
		}},
		{"prc002-undefined-scheme.yaml", []string{"PRC002"}, []string{
			"PRC002 prc002-undefined-scheme.yaml:10:7 GET /orders",
		}},
		// OpenAPI 3.2 allows a URI reference as the scheme name: not undefined.
		{"prc002-uri-reference-3.2.yaml", []string{"PRC002"}, []string{}},
		{"prc002-undefined-global.yaml", []string{"PRC002"}, []string{
			"PRC002 prc002-undefined-global.yaml:5:1 ",
		}},
		{"prc003-weak-schemes.yaml", []string{"PRC003"}, []string{
			"PRC003 prc003-weak-schemes.yaml:13:5 ",
			"PRC003 prc003-weak-schemes.yaml:21:5 ",
		}},
		{"prc011-oauth-flows.yaml", []string{"PRC011"}, []string{
			"PRC011 prc011-oauth-flows.yaml:11:9 ",
			"PRC011 prc011-oauth-flows.yaml:14:9 ",
		}},
		// /admin/users inherits the default: reported. /admin/orders has
		// its own scope: not. /internal/metrics repeats the default: reported.
		// /debug-tools has "debug" as a word: reported. /administrators-guide
		// is not "admin". /management has no auth at all: PRC001, not PRC010.
		// No default security: /admin/users is protected exactly like /orders
		// (same alternatives and scopes, in another order). /admin/orders asks
		// for a scope no regular operation uses.
		{"prc010-no-default.yaml", []string{"PRC010"}, []string{
			"PRC010 prc010-no-default.yaml:15:5 GET /admin/users",
		}},
		{"prc010-admin.yaml", []string{"PRC001", "PRC010"}, []string{
			"PRC010 prc010-admin.yaml:9:5 GET /admin/users",
			"PRC010 prc010-admin.yaml:21:5 GET /internal/metrics",
			"PRC010 prc010-admin.yaml:28:5 DELETE /debug-tools/cache",
			"PRC001 prc010-admin.yaml:38:5 GET /management",
		}},
		{"prc008-limits.yaml", []string{"PRC008"}, []string{
			"PRC008 prc008-limits.yaml:9:5 GET /orders",
			"PRC008 prc008-limits.yaml:26:17 POST /orders",
			"PRC008 prc008-limits.yaml:40:17 POST /orders",
			"PRC008 prc008-limits.yaml:49:17 POST /orders",
			"PRC008 prc008-limits.yaml:58:23 POST /orders",
			"PRC008 prc008-limits.yaml:101:13 POST /bulk",
			"PRC008 prc008-limits.yaml:126:5 GET /stats",
		}},
		{"prc008-nullable-3.1.yaml", []string{"PRC008"}, []string{
			"PRC008 prc008-nullable-3.1.yaml:9:5 GET /notes",
			"PRC008 prc008-nullable-3.1.yaml:30:17 POST /notes",
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
