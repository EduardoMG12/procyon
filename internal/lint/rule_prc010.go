package lint

import (
	"reflect"
	"slices"
	"strings"
	"unicode"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc010 = Rule{
	ID:       "PRC010",
	Title:    "Admin operation uses only the default security",
	Severity: Medium,
	OWASP:    "API5:2023 Broken Function Level Authorization",
	check:    checkPRC010,
}

// adminWords are path words that mark an operation as administrative.
var adminWords = []string{"admin", "internal", "debug", "management"}

// checkPRC010 reports authenticated operations under an admin-like path that
// are protected exactly like every other operation: any logged-in user can
// probably call them. Unauthenticated ones are PRC001's.
func checkPRC010(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !adminPath(path) || unauthenticated(doc, op) {
			return
		}
		if op.Security != nil && !reflect.DeepEqual(*op.Security, doc.Security) {
			return // it declares something of its own
		}
		findings = append(findings, Finding{
			Location:  locate(op.Origin),
			Operation: method + " " + path,
			Why:       "This looks like an administrative operation, but it requires the same authentication as every other operation: any logged-in user may be able to call it.",
			Fix:       "Give it a stricter requirement of its own, such as an admin-only OAuth2 scope or a separate scheme, and enforce it on the server.",
		})
	})
	return findings
}

// adminPath reports whether a path segment, split into words on anything
// but letters and digits, contains an admin word: /admin/users and
// /debug-tools match, /administrators-guide does not.
func adminPath(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		words := strings.FieldsFunc(strings.ToLower(segment), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		for _, w := range words {
			if slices.Contains(adminWords, w) {
				return true
			}
		}
	}
	return false
}
