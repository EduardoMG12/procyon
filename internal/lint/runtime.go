package lint

import (
	"cmp"
	"slices"
	"time"
)

// Runtime rules are checked by `procyon test` against a running API, not by
// linting the spec. Their catalog lives here, next to the lint rules, so an
// x-procyon-ignore can name either kind and a typo in either is caught.
// They have no check: internal/test produces their findings.
var runtimeRules = []Rule{prc101, prc102}

var prc101 = Rule{
	ID:       "PRC101",
	Title:    "Anonymous caller reached an operation that requires authentication",
	Severity: Critical,
	OWASP:    "API2:2023 Broken Authentication",
}

var prc102 = Rule{
	ID:       "PRC102",
	Title:    "Another account reached A's object",
	Severity: Critical,
	OWASP:    "API1:2023 Broken Object Level Authorization",
}

// RuntimeRules returns every runtime rule, in ID order.
func RuntimeRules() []Rule {
	return slices.Clone(runtimeRules)
}

// RuntimeRule returns the runtime rule with the given ID. It panics on an
// unknown ID: that is a bug in Procyon, not in a spec.
func RuntimeRule(id string) Rule {
	i := slices.IndexFunc(runtimeRules, func(r Rule) bool { return r.ID == id })
	if i < 0 {
		panic("lint: unknown runtime rule " + id)
	}
	return runtimeRules[i]
}

// Exchange is one request a runtime test sent and what it got: the
// evidence behind a runtime finding. Credentials never appear in it.
type Exchange struct {
	Caller string // "anonymous", "A" or "B"
	Method string
	URL    string // the path and query, as sent: "/notes/1"
	Status int
	Body   string // the start of the response body
}

// MatrixRow is one operation of a runtime test's authorization matrix:
// what each caller got from it.
type MatrixRow struct {
	Operation       string // "GET /notes/{id}"
	A, B, Anonymous Cell
}

// Cell is what one caller got from one operation.
type Cell struct {
	Outcome Outcome
	Status  int // the HTTP status, when the operation was called
}

// Outcome is how a call ended, for the authorization matrix.
type Outcome string

const (
	NotCalled Outcome = ""        // this caller is not tested on this operation
	Allowed   Outcome = "allowed" // a 2xx, as expected
	Denied    Outcome = "denied"  // not a 2xx
	Reached   Outcome = "finding" // a 2xx that is a finding (PRC101, PRC102)
	Public    Outcome = "public"  // x-procyon-public, not called anonymously
	Skipped   Outcome = "skipped" // could not be called; a note says why
)

// Finish turns the findings and notes of a runtime test of this spec into a
// report, the way Run does for a lint: sorted, with the spec's ignores of
// runtime rules applied and the fail threshold checked.
func (s *Spec) Finish(findings []Finding, notes []Note, opts Options) Report {
	report := Report{FailOn: cmp.Or(opts.FailOn, High), Sources: s.files.lines, Findings: findings}
	sortFindings(report.Findings)
	today := opts.Today
	if today.IsZero() {
		today = time.Now()
	}
	applyIgnores(&report, ignoresOf(s.ignores, runtimeRules), today)
	report.Notes = slices.Concat(notes, report.Notes)
	report.Failed = failed(report)
	return report
}

// ignoresOf keeps the ignores of the given rules, so a lint never calls an
// ignore of a runtime rule unused, and a runtime test never calls an ignore
// of a lint rule unused.
func ignoresOf(ignores []*ignore, rules []Rule) []*ignore {
	var kept []*ignore
	for _, ig := range ignores {
		if slices.ContainsFunc(rules, func(r Rule) bool { return r.ID == ig.rule }) {
			kept = append(kept, ig)
		}
	}
	return kept
}

// sortFindings orders findings by where they point, so the same input
// always gives the same report.
func sortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Location.File, b.Location.File),
			cmp.Compare(a.Location.Line, b.Location.Line),
			cmp.Compare(a.Location.Column, b.Location.Column),
			cmp.Compare(a.Rule.ID, b.Rule.ID),
		)
	})
}

// failed reports whether a finding is at or above the fail threshold.
func failed(report Report) bool {
	return slices.ContainsFunc(report.Findings, func(f Finding) bool { return f.Rule.Severity >= report.FailOn })
}
