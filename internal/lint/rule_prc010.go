package lint

import (
	"slices"
	"strings"
	"unicode"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/EduardoMG12/procyon/internal/words"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc010 = lintRule{
	Rule: report.Rule{
		ID:       "PRC010",
		Title:    "Admin operation uses only the default security",
		Severity: report.Medium,
		OWASP:    "API5:2023 Broken Function Level Authorization",
	},
	check: checkPRC010,
}

// adminWords are path words that mark an operation as administrative.
var adminWords = []string{"admin", "internal", "debug", "management"}

// checkPRC010 reports authenticated operations under an admin-like path
// whose security is exactly that of some regular operation: whoever can
// call the regular one can probably call the admin one. Comparing with
// regular operations, not with the spec's default, also works for specs
// that repeat security on every operation. Unauthenticated operations are
// PRC001's.
func checkPRC010(doc *openapi3.T) []report.Finding {
	regular := map[string]bool{}
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !adminPath(path) && !loader.Unauthenticated(doc, path, op) {
			regular[authKey(doc, path, op)] = true
		}
	})
	var findings []report.Finding
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !adminPath(path) || loader.Unauthenticated(doc, path, op) || !regular[authKey(doc, path, op)] {
			return
		}
		findings = append(findings, report.Finding{
			Location:  loader.Locate(op.Origin),
			Operation: method + " " + path,
			Why:       "This looks like an administrative operation, but it requires the same authentication as regular operations: any user who can call those may be able to call this.",
			Fix:       "Give it a stricter requirement of its own, such as an admin-only OAuth2 scope or a separate scheme, and enforce it on the server.",
		})
	})
	return findings
}

// authKey is equal for operations that authenticate the same way: the same
// security requirements and the same credential parameter, if any.
func authKey(doc *openapi3.T, path string, op *openapi3.Operation) string {
	key := securityKey(loader.EffectiveSecurity(doc, op))
	if name := loader.CredentialParameter(doc, path, op); name != "" {
		key += " parameter " + strings.ToLower(name)
	}
	return key
}

// securityKey turns requirements into a string that is equal for equal
// requirements. OpenAPI does not order alternatives, schemes or scopes, so
// each level is sorted: [{apiKey}, {oauth: [read, write]}] and
// [{oauth: [write, read]}, {apiKey}] get the same key.
func securityKey(reqs openapi3.SecurityRequirements) string {
	alternatives := make([]string, 0, len(reqs))
	for _, req := range reqs {
		schemes := make([]string, 0, len(req))
		for name, scopes := range req {
			sorted := slices.Sorted(slices.Values(scopes))
			schemes = append(schemes, name+"("+strings.Join(sorted, ",")+")")
		}
		slices.Sort(schemes)
		alternatives = append(alternatives, strings.Join(schemes, "&"))
	}
	slices.Sort(alternatives)
	return strings.Join(alternatives, "|")
}

// adminPath reports whether a path segment, split into words on anything
// but letters and digits, contains an admin word or its plural:
// /admin/users, /orgs/{org}/admins and /debug-tools match,
// /administrators-guide and /users/{admin_id} (a parameter's name) do not.
func adminPath(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, "{") {
			continue // a parameter's name ({admin_id}) is not part of the path
		}
		parts := strings.FieldsFunc(strings.ToLower(segment), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		for _, w := range parts {
			if slices.ContainsFunc(adminWords, func(a string) bool { return words.Same(w, a) }) { // admins too
				return true
			}
		}
	}
	return false
}
