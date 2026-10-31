// Package lint checks an OpenAPI or Swagger spec for security problems in
// its design, without calling the API. Each rule reads the loaded spec and
// returns findings, one rule per file; Run hands them to report.New, which
// applies ignores and the fail threshold. The runtime rules' catalog lives
// here too (runtime.go), so an x-procyon-ignore can name any rule.
package lint

import (
	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// lintRule is one lint rule: what reports show about it, and its check.
type lintRule struct {
	report.Rule
	// check returns the rule's findings; Run fills in Finding.Rule.
	check func(doc *openapi3.T) []report.Finding
}

// Rules returns every lint rule, in ID order.
func Rules() []report.Rule {
	out := make([]report.Rule, len(rules))
	for i, r := range rules {
		out[i] = r.Rule
	}
	return out
}

// rules is every lint rule, in ID order.
var rules = []lintRule{prc001, prc002, prc003, prc004, prc005, prc006, prc007, prc008, prc009, prc010, prc011}
