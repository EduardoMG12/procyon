package lint

import (
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/getkin/kin-openapi/openapi3"
)

var prc011 = lintRule{
	Rule: report.Rule{
		ID:       "PRC011",
		Title:    "OAuth2 flow is deprecated",
		Severity: report.Medium,
		OWASP:    "API2:2023 Broken Authentication",
	},
	check: checkPRC011,
}

// checkPRC011 reports OAuth2 schemes offering the implicit or password flow,
// both removed by the OAuth 2.0 Security Best Current Practice (RFC 9700).
func checkPRC011(doc *openapi3.T) []report.Finding {
	var findings []report.Finding
	loader.ForEachScheme(doc, func(name string, scheme *openapi3.SecurityScheme) {
		flows := scheme.Flows
		if flows == nil {
			return
		}
		if flows.Implicit != nil {
			findings = append(findings, report.Finding{
				Location: loader.LocateField(flows.Origin, "implicit"),
				Element:  flows.Implicit,
				Why:      "The implicit flow returns the access token in the browser's URL, where history, logs and other scripts can read it, and it cannot prove who asked for the token.",
				Fix:      "Use the authorizationCode flow with PKCE.",
			})
		}
		if flows.Password != nil {
			findings = append(findings, report.Finding{
				Location: loader.LocateField(flows.Origin, "password"),
				Element:  flows.Password,
				Why:      "The password flow makes the client collect the user's real password, so every client becomes a place where passwords leak, and it cannot support multi-factor login.",
				Fix:      "Use the authorizationCode flow with PKCE for users, or clientCredentials for machine-to-machine access.",
			})
		}
	})
	return findings
}
