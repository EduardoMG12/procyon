package lint

import (
	"github.com/getkin/kin-openapi/openapi3"
)

var prc011 = Rule{
	ID:       "PRC011",
	Title:    "OAuth2 flow is deprecated",
	Severity: Medium,
	OWASP:    "API2:2023 Broken Authentication",
	check:    checkPRC011,
}

// checkPRC011 reports OAuth2 schemes offering the implicit or password flow,
// both removed by the OAuth 2.0 Security Best Current Practice (RFC 9700).
func checkPRC011(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachScheme(doc, func(name string, scheme *openapi3.SecurityScheme) {
		flows := scheme.Flows
		if flows == nil {
			return
		}
		if flows.Implicit != nil {
			findings = append(findings, Finding{
				Location: locateField(flows.Origin, "implicit"),
				about:    flows.Implicit,
				Why:      "The implicit flow returns the access token in the browser's URL, where history, logs and other scripts can read it, and it cannot prove who asked for the token.",
				Fix:      "Use the authorizationCode flow with PKCE.",
			})
		}
		if flows.Password != nil {
			findings = append(findings, Finding{
				Location: locateField(flows.Origin, "password"),
				about:    flows.Password,
				Why:      "The password flow makes the client collect the user's real password, so every client becomes a place where passwords leak, and it cannot support multi-factor login.",
				Fix:      "Use the authorizationCode flow with PKCE for users, or clientCredentials for machine-to-machine access.",
			})
		}
	})
	return findings
}
