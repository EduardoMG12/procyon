package lint

import (
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc001 = lintRule{
	Rule: report.Rule{
		ID:       "PRC001",
		Title:    "Operation has no authentication",
		Severity: report.High,
		OWASP:    "API2:2023 Broken Authentication",
	},
	check: checkPRC001,
}

// checkPRC001 reports operations anyone can call without credentials,
// unless they are marked public (x-procyon-public).
func checkPRC001(doc *openapi3.T) []report.Finding {
	var findings []report.Finding
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !loader.Unauthenticated(doc, path, op) || loader.PublicReason(op) != "" {
			return
		}
		findings = append(findings, report.Finding{
			Location:  loader.Locate(op.Origin),
			Operation: method + " " + path,
			Why:       "Anyone who can reach the API can call this operation, without proving who they are.",
			Fix:       "Add a security requirement to the operation or to the whole spec.",
		})
	})
	return findings
}
