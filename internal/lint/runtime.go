package lint

import (
	"cmp"
	"slices"
	"time"

	"github.com/EduardoMG12/procyon/internal/report"
)

// Runtime rules are checked by `procyon test` against a running API, not by
// linting the spec. Their catalog lives here, next to the lint rules, so an
// x-procyon-ignore can name either kind and a typo in either is caught.
// They have no check: internal/test produces their findings.
var runtimeRules = []report.Rule{prc101, prc102, prc103, prc104, prc105}

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

// Finish turns the findings and notes of a runtime test of this spec into a
// report, the way Run does for a lint: sorted, with the spec's ignores of
// runtime rules applied and the fail threshold checked.
func (s *Spec) Finish(findings []report.Finding, notes []report.Note, opts Options) report.Report {
	// A finding about no operation (PRC105, the target's TLS) is about the
	// spec as a whole: an ignore at the spec's root covers it.
	for i := range findings {
		if findings[i].Operation == "" && findings[i].Element == nil {
			findings[i].Element = s.doc
		}
	}
	rep := report.Report{FailOn: cmp.Or(opts.FailOn, report.High), Sources: s.files.lines, Findings: findings}
	sortFindings(rep.Findings)
	today := opts.Today
	if today.IsZero() {
		today = time.Now()
	}
	applyIgnores(&rep, ignoresOf(s.ignores, runtimeRules), today)
	rep.Notes = slices.Concat(notes, rep.Notes)
	rep.Failed = failed(rep)
	return rep
}

// ignoresOf keeps the ignores of the given rules, so a lint never calls an
// ignore of a runtime rule unused, and a runtime test never calls an ignore
// of a lint rule unused.
func ignoresOf(ignores []*ignore, rules []report.Rule) []*ignore {
	var kept []*ignore
	for _, ig := range ignores {
		if slices.ContainsFunc(rules, func(r report.Rule) bool { return r.ID == ig.rule }) {
			kept = append(kept, ig)
		}
	}
	return kept
}

// sortFindings orders findings by where they point, so the same input
// always gives the same report.
func sortFindings(findings []report.Finding) {
	slices.SortStableFunc(findings, func(a, b report.Finding) int {
		return cmp.Or(
			cmp.Compare(a.Location.File, b.Location.File),
			cmp.Compare(a.Location.Line, b.Location.Line),
			cmp.Compare(a.Location.Column, b.Location.Column),
			cmp.Compare(a.Rule.ID, b.Rule.ID),
		)
	})
}

// failed reports whether a finding is at or above the fail threshold.
func failed(rep report.Report) bool {
	return slices.ContainsFunc(rep.Findings, func(f report.Finding) bool { return f.Rule.Severity >= rep.FailOn })
}
