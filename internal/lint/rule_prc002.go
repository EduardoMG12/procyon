package lint

import (
	"fmt"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc002 = Rule{
	ID:       "PRC002",
	Title:    "Security requirement names an undefined scheme",
	Severity: High,
	OWASP:    "API2:2023 Broken Authentication",
	check:    checkPRC002,
}

// checkPRC002 reports requirements that name a scheme components does not
// define. kin-openapi rejects these as invalid; Procyon reports them as a
// finding instead, because what they mean in practice is an operation whose
// documented protection does not exist.
func checkPRC002(doc *openapi3.T) []Finding {
	var findings []Finding
	report := func(reqs openapi3.SecurityRequirements, origin *openapi3.Origin, operation string) {
		for _, name := range undefinedSchemes(doc, reqs) {
			findings = append(findings, Finding{
				Location:  locateField(origin, "security"),
				Operation: operation,
				Why: fmt.Sprintf("The requirement names the scheme %q, which the spec never defines, "+
					"so the protection it documents does not exist: clients and gateways built from the spec cannot authenticate, "+
					"and nothing says how the operation is really protected.", name),
				Fix: fmt.Sprintf("Define %q under components.securitySchemes, or fix the name to match a defined scheme.", name),
			})
		}
	}
	report(doc.Security, doc.Origin, "")
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.Security != nil {
			report(*op.Security, op.Origin, method+" "+path)
		}
	})
	return findings
}

// undefinedSchemes returns, sorted, the scheme names reqs use that the spec
// does not define.
func undefinedSchemes(doc *openapi3.T, reqs openapi3.SecurityRequirements) []string {
	var defined openapi3.SecuritySchemes
	if doc.Components != nil {
		defined = doc.Components.SecuritySchemes
	}
	seen := map[string]bool{}
	var names []string
	for _, req := range reqs {
		for name := range req {
			if _, ok := defined[name]; !ok && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}
