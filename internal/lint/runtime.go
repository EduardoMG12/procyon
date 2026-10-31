package lint

import (
	"slices"

	"github.com/EduardoMG12/procyon/internal/report"
)

// Runtime rules are checked by `procyon test` against a running API, not by
// linting the spec. Their catalog lives here, next to the lint rules, so an
// x-procyon-ignore can name either kind and a typo in either is caught.
// They have no check: internal/probe produces their findings.
var runtimeRules = []report.Rule{prc101, prc102, prc103, prc104, prc105, prc106, prc108, prc109}

var prc101 = report.Rule{
	ID:       "PRC101",
	Title:    "Anonymous caller reached an operation that requires authentication",
	Severity: report.Critical,
	OWASP:    "API2:2023 Broken Authentication",
}

var prc102 = report.Rule{
	ID:       "PRC102",
	Title:    "Another account reached A's object",
	Severity: report.Critical,
	OWASP:    "API1:2023 Broken Object Level Authorization",
}

var prc103 = report.Rule{
	ID:       "PRC103",
	Title:    "Malformed request made the server fail",
	Severity: report.Medium,
	OWASP:    "API8:2023 Security Misconfiguration",
}

var prc104 = report.Rule{
	ID:       "PRC104",
	Title:    "Server accepted a request the spec forbids",
	Severity: report.Low,
	OWASP:    "API8:2023 Security Misconfiguration",
}

var prc105 = report.Rule{
	ID:       "PRC105",
	Title:    "The API's TLS is weak",
	Severity: report.High,
	OWASP:    "API8:2023 Security Misconfiguration",
}

var prc106 = report.Rule{
	ID:       "PRC106",
	Title:    "Public operation returned personal data",
	Severity: report.High,
	OWASP:    "API3:2023 Broken Object Property Level Authorization",
}

var prc108 = report.Rule{
	ID:       "PRC108",
	Title:    "Another account's list shows A's objects",
	Severity: report.Critical,
	OWASP:    "API1:2023 Broken Object Level Authorization",
}

var prc109 = report.Rule{
	ID:       "PRC109",
	Title:    "A response shows an internal error",
	Severity: report.Medium,
	OWASP:    "API8:2023 Security Misconfiguration",
}

// RuntimeRules returns every runtime rule, in ID order.
func RuntimeRules() []report.Rule {
	return slices.Clone(runtimeRules)
}

// RuntimeRule returns the runtime rule with the given ID. It panics on an
// unknown ID: that is a bug in Procyon, not in a spec.
func RuntimeRule(id string) report.Rule {
	i := slices.IndexFunc(runtimeRules, func(r report.Rule) bool { return r.ID == id })
	if i < 0 {
		panic("lint: unknown runtime rule " + id)
	}
	return runtimeRules[i]
}

// KnownRule reports whether id names a rule, lint or runtime: what an
// x-procyon-ignore may name.
func KnownRule(id string) bool {
	return slices.ContainsFunc(rules, func(r lintRule) bool { return r.ID == id }) ||
		slices.ContainsFunc(runtimeRules, func(r report.Rule) bool { return r.ID == id })
}
