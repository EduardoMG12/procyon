package lint_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/report"
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
		// Swagger 2.0: findings point at the original file, not the
		// OpenAPI 3 document it is converted to.
		// Swagger 2.0 in JSON, with the request body as a "body" parameter.
		{"swagger-2.0-body.json", []string{"PRC009"}, []string{
			"PRC009 swagger-2.0-body.json:18:17 POST /users",
		}},
		// Swagger 2.0 edges: a global body parameter, a global response, a
		// body declared on the path item and shared by two operations (one
		// finding each, at the property; two media types add none), and ignores for
		// PRC004 at the root and PRC011 on the scheme that holds its flow.
		{"swagger-2.0-edges.yaml", []string{"PRC004", "PRC005", "PRC009", "PRC011"}, []string{
			"PRC009 swagger-2.0-edges.yaml:33:9 POST /admins",
			"PRC005 swagger-2.0-edges.yaml:41:9 GET /me",
			"PRC009 swagger-2.0-edges.yaml:51:13 POST /accounts",
			"PRC009 swagger-2.0-edges.yaml:51:13 PUT /accounts",
		}},
		// Swagger 2.0: formData fields, an operation-level http scheme, a
		// path-level body whose POST copy is ignored but PUT copy is not,
		// and nulls inside examples and x- extensions (valid).
		{"swagger-2.0-forms.yaml", []string{"PRC004", "PRC008", "PRC009"}, []string{
			"PRC009 swagger-2.0-forms.yaml:19:11 POST /profile",
			"PRC008 swagger-2.0-forms.yaml:23:11 POST /profile",
			"PRC004 swagger-2.0-forms.yaml:31:7 POST /login",
			"PRC009 swagger-2.0-forms.yaml:42:13 PUT /accounts",
		}},
		// Swagger 2.0: an x- extension under paths is not a path item, and a
		// formData field given by $ref points at that $ref.
		{"swagger-2.0-extensions.yaml", []string{"PRC009"}, []string{
			"PRC009 swagger-2.0-extensions.yaml:22:11 POST /profile",
		}},
		// A schema shared by two operations, with the finding ignored on one:
		// the other still reports it.
		{"prc009-shared-ignore.yaml", []string{"PRC009"}, []string{
			"PRC009 prc009-shared-ignore.yaml:41:9 POST /register",
		}},
		// One path item file used by two paths: two endpoints, two findings
		// each, at the same place.
		{"shared-path-item/spec.yaml", []string{"PRC001", "PRC007"}, []string{
			"PRC001 item.yaml:1:1 GET /admins/{id}",
			"PRC001 item.yaml:1:1 GET /users/{id}",
			"PRC007 item.yaml:1:1 GET /admins/{id}",
			"PRC007 item.yaml:1:1 GET /users/{id}",
		}},
		// Numbers that set how much work a request makes (repeats, page size,
		// retries) need a maximum. Not reported: a maximum, an enum, an
		// operation overriding a path-level parameter with a maximum, and
		// names where the word means a stored or physical value (creditLimit,
		// marginTop, waterDepth, stockCount, retryAfter, repeatEvery).
		{"prc008-counts.yaml", []string{"PRC008"}, []string{
			"PRC008 prc008-counts.yaml:11:11 GET /items",
			"PRC008 prc008-counts.yaml:39:11 GET /orders",
			"PRC008 prc008-counts.yaml:48:9 GET /search",
			"PRC008 prc008-counts.yaml:69:11 POST /exports",
			"PRC008 prc008-counts.yaml:84:17 POST /reports",
			"PRC008 prc008-counts.yaml:94:17 POST /reports",
			"PRC008 prc008-counts.yaml:96:17 POST /reports",
		}},
		// A credential sent as a required header or query parameter
		// (x-access-token, Authorization, api_key), as older specs do, is
		// authentication. An optional one is not, nor a CSRF, captcha or
		// request token, nor a bare token (a one-time link's).
		{"prc001-credential-parameter.yaml", []string{"PRC001"}, []string{
			"PRC001 prc001-credential-parameter.yaml:43:5 GET /items",
			"PRC001 prc001-credential-parameter.yaml:54:5 GET /cart",
			"PRC001 prc001-credential-parameter.yaml:66:5 POST /password/reset",
			"PRC001 prc001-credential-parameter.yaml:78:5 POST /signup",
		}},
		// Credentials sent as parameters are told apart by name: an admin
		// key differs from the users' key, the same key does not.
		{"prc010-credential-parameter.yaml", []string{"PRC010"}, []string{
			"PRC010 prc010-credential-parameter.yaml:31:5 DELETE /admin/orders",
		}},
		// A secret is a value: text, a number, or a list of them. Objects
		// that point at a secret (secretRef, imagePullSecrets, an anyOf of
		// objects) and fields describing one (secretNamespace,
		// token_risk_score) are not reported.
		{"prc005-references.yaml", []string{"PRC005"}, []string{
			"PRC005 prc005-references.yaml:38:19 GET /volumes",
			"PRC005 prc005-references.yaml:40:19 GET /volumes",
			"PRC005 prc005-references.yaml:46:19 GET /volumes",
			"PRC005 prc005-references.yaml:59:19 GET /volumes",
			"PRC005 prc005-references.yaml:63:19 GET /volumes",
			"PRC005 prc005-references.yaml:68:19 GET /volumes",
			"PRC005 prc005-references.yaml:70:19 GET /volumes",
		}},
		// A role on /memberships/{username} is what the operation assigns,
		// and an enum of only low values (guestRole: viewer | commenter)
		// cannot grant anything. Everything else still counts: tenantId or
		// isAdmin on a grant path, a /members collection, /permissions-check,
		// boolean, numeric and tenant enums, superadmin, delete:users.
		{"prc009-grants-and-enums.yaml", []string{"PRC009"}, []string{
			"PRC009 prc009-grants-and-enums.yaml:32:17 PUT /orgs/{org}/memberships/{username}",
			"PRC009 prc009-grants-and-enums.yaml:53:17 PATCH /orgs/{org}/settings", // write_scope: values not known to be low
			"PRC009 prc009-grants-and-enums.yaml:56:17 PATCH /orgs/{org}/settings",
			"PRC009 prc009-grants-and-enums.yaml:62:17 PATCH /orgs/{org}/settings",
			"PRC009 prc009-grants-and-enums.yaml:67:17 PATCH /orgs/{org}/settings",
			"PRC009 prc009-grants-and-enums.yaml:87:17 PUT /members/{id}",
			"PRC009 prc009-grants-and-enums.yaml:100:17 POST /api/members",
			"PRC009 prc009-grants-and-enums.yaml:114:17 POST /permissions-check",
			"PRC009 prc009-grants-and-enums.yaml:128:17 PATCH /flags",
			"PRC009 prc009-grants-and-enums.yaml:131:17 PATCH /flags",
			"PRC009 prc009-grants-and-enums.yaml:134:17 PATCH /flags",
			"PRC009 prc009-grants-and-enums.yaml:137:17 PATCH /flags",
			"PRC009 prc009-grants-and-enums.yaml:140:17 PATCH /flags",
		}},
		// Admin words count in the path's own segments, plural included
		// (/admins), not in a parameter's name (/users/{admin_id}).
		{"prc010-path-words.yaml", []string{"PRC010"}, []string{
			"PRC010 prc010-path-words.yaml:26:5 GET /orgs/{org}/admins",
		}},
		// Two undefined schemes in one requirement are two findings.
		{"prc002-two-undefined.yaml", []string{"PRC002"}, []string{
			"PRC002 prc002-two-undefined.yaml:5:1 ",
			"PRC002 prc002-two-undefined.yaml:5:1 ",
		}},
		{"swagger-2.0-shop.yaml", []string{"PRC001", "PRC003", "PRC004", "PRC005", "PRC007"}, []string{
			"PRC004 swagger-2.0-shop.yaml:7:1 ",
			"PRC003 swagger-2.0-shop.yaml:10:3 ",
			"PRC001 swagger-2.0-shop.yaml:14:5 GET /users/{id}",
			"PRC007 swagger-2.0-shop.yaml:14:5 GET /users/{id}",
			"PRC005 swagger-2.0-shop.yaml:29:7 GET /users/{id}",
		}},
		// Authenticated: nothing. Unauthenticated (/profiles) and public (/team)
		// operations: both rules. /docs/{version}: version is not an object ID.
		{"prc006-prc007.yaml", []string{"PRC006", "PRC007"}, []string{
			"PRC007 prc006-prc007.yaml:24:5 GET /profiles/{username}",
			"PRC007 prc006-prc007.yaml:39:5 GET /team/{order_id}/contacts",
			"PRC006 prc006-prc007.yaml:57:21 GET /team/{order_id}/contacts",
			"PRC006 prc006-prc007.yaml:96:19 GET /contacts",
			"PRC006 prc006-prc007.yaml:100:19 GET /contacts",
			"PRC006 prc006-prc007.yaml:102:19 GET /contacts",
			"PRC006 prc006-prc007.yaml:106:19 GET /contacts",
			"PRC007 prc006-prc007.yaml:118:5 GET /orders/{orderid}",
			"PRC006 prc006-prc007.yaml:157:9 GET /profiles/{username}",
			"PRC006 prc006-prc007.yaml:161:9 GET /profiles/{username}",
			"PRC006 prc006-prc007.yaml:163:9 GET /profiles/{username}",
			"PRC006 prc006-prc007.yaml:165:9 GET /profiles/{username}",
			"PRC006 prc006-prc007.yaml:170:9 GET /profiles/{username}",
		}},
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
		// No default security: /admin/users is protected exactly like /orders
		// (same alternatives and scopes, in another order). /admin/orders asks
		// for a scope no regular operation uses.
		{"prc010-no-default.yaml", []string{"PRC010"}, []string{
			"PRC010 prc010-no-default.yaml:15:5 GET /admin/users",
		}},
		// /admin/users inherits the default: reported. /admin/orders has
		// its own scope: not. /internal/metrics repeats the default: reported.
		// /debug-tools has "debug" as a word: reported. /administrators-guide
		// is not "admin". /management has no auth at all: PRC001, not PRC010.
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
			"PRC008 prc008-limits.yaml:83:11 GET /customers", // per_page without maximum
			"PRC008 prc008-limits.yaml:101:13 POST /bulk",
			"PRC008 prc008-limits.yaml:112:11 GET /odata/orders", // $top without maximum
			"PRC008 prc008-limits.yaml:126:5 GET /stats",
		}},
		{"prc008-nullable-3.1.yaml", []string{"PRC008"}, []string{
			"PRC008 prc008-nullable-3.1.yaml:9:5 GET /notes",
			"PRC008 prc008-nullable-3.1.yaml:30:17 POST /notes",
		}},
		{"prc009-mass-assignment.yaml", []string{"PRC009"}, []string{
			"PRC009 prc009-mass-assignment.yaml:34:17 PATCH /users/{id}",
			"PRC009 prc009-mass-assignment.yaml:96:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:98:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:100:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:104:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:108:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:120:13 POST /users",
			"PRC009 prc009-mass-assignment.yaml:122:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:126:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:130:9 POST /users",
			"PRC009 prc009-mass-assignment.yaml:132:9 POST /users",
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
		// Schemas that refer to themselves end: a map of maps, a list of
		// lists, an allOf of itself and a value wrapping itself hold no
		// value; a map of text or nested maps does.
		{"prc005-recursive.yaml", []string{"PRC005"}, []string{
			"PRC005 prc005-recursive.yaml:26:19 GET /documents",
		}},
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
			rep, err := lint.Run(spec(tt.spec), lint.Options{})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := summarize(rep.Findings, tt.rules)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings:\n got  %q\n want %q", got, tt.want)
			}
		})
	}
}

func summarize(findings []report.Finding, rules []string) []string {
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
