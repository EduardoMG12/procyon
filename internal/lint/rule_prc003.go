package lint

import (
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc003 = Rule{
	ID:       "PRC003",
	Title:    "Weak authentication scheme",
	Severity: Medium,
	OWASP:    "API2:2023 Broken Authentication",
	check:    checkPRC003,
}

// checkPRC003 reports API keys sent in the query string and HTTP Basic.
func checkPRC003(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachScheme(doc, func(name string, scheme *openapi3.SecurityScheme) {
		var why, fix string
		switch {
		case strings.EqualFold(scheme.Type, "apiKey") && strings.EqualFold(scheme.In, "query"):
			why = "An API key in the query string ends up in server logs, proxy logs, browser history and Referer headers, where anyone who reads them can reuse it."
			fix = "Send the key in a header instead (in: header), or move to a bearer token."
		case strings.EqualFold(scheme.Type, "http") && strings.EqualFold(scheme.Scheme, "basic"):
			why = "HTTP Basic sends the user's real password with every request, so one leaked request leaks the password, and it cannot expire or be scoped."
			fix = "Exchange the password once for a short-lived token (OAuth2 or a bearer token) and send that instead."
		default:
			return
		}
		findings = append(findings, Finding{Location: locate(scheme.Origin), Why: why, Fix: fix})
	})
	return findings
}

// forEachScheme calls fn for every defined security scheme.
func forEachScheme(doc *openapi3.T, fn func(name string, scheme *openapi3.SecurityScheme)) {
	if doc.Components == nil {
		return
	}
	for name, ref := range doc.Components.SecuritySchemes {
		if ref != nil && ref.Value != nil {
			fn(name, ref.Value)
		}
	}
}
