package lint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc002 = lintRule{
	Rule: report.Rule{
		ID:       "PRC002",
		Title:    "Security requirement names an undefined scheme",
		Severity: report.High,
		OWASP:    "API2:2023 Broken Authentication",
	},
	check: checkPRC002,
}

// checkPRC002 reports requirements that name a scheme components does not
// define. kin-openapi rejects these as invalid; Procyon reports them as a
// finding instead, because what they mean in practice is an operation whose
// documented protection does not exist.
func checkPRC002(doc *openapi3.T) []report.Finding {
	var findings []report.Finding
	flag := func(reqs openapi3.SecurityRequirements, origin *openapi3.Origin, operation string, about any) {
		for _, name := range undefinedSchemes(doc, reqs) {
			findings = append(findings, report.Finding{
				Location:  loader.LocateField(origin, "security"),
				Operation: operation,
				Element:   about,
				Why: fmt.Sprintf("The requirement names the scheme %q, which the spec never defines, "+
					"so the protection it documents does not exist: clients and gateways built from the spec cannot authenticate, "+
					"and nothing says how the operation is really protected.", name),
				Fix: fmt.Sprintf("Define %q under components.securitySchemes, or fix the name to match a defined scheme.", name),
			})
		}
	}
	flag(doc.Security, doc.Origin, "", doc)
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.Security != nil {
			flag(*op.Security, op.Origin, method+" "+path, op)
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
			if uriReference(doc, name) {
				continue
			}
			if _, ok := defined[name]; !ok && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// uriReference reports whether name is a URI reference to a scheme rather
// than a key of components.securitySchemes. OpenAPI 3.2 allows those;
// resolving them would mean reading other documents, so they are not
// checked. Component keys can only contain letters, digits, ".", "-" and
// "_", so anything with "/", "#" or ":" is a reference.
func uriReference(doc *openapi3.T, name string) bool {
	return doc.IsOpenAPI32OrLater() && strings.ContainsAny(name, "/#:")
}
