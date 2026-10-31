// Package report is what a Procyon run produces, whatever produced it: the
// lint rules or the runtime tests. Formats read only this package, so they
// can never decide what is a finding.
package report

import "fmt"

// Severity is how serious a finding is. The order matters: a higher value is
// more serious, which is how the fail threshold compares them.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// ParseSeverity reads a severity name as written in flags and config.
func ParseSeverity(name string) (Severity, error) {
	for s := Low; s <= Critical; s++ {
		if s.String() == name {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (use critical, high, medium, low)", name)
}

// Rule is one security check's identity: what every format shows about it.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	OWASP    string // OWASP API Security Top 10 (2023) category
}

// DocsURL is the page that explains the rule.
func (r Rule) DocsURL() string {
	return "https://github.com/EduardoMG12/procyon/blob/main/docs/rules/" + r.ID + ".md"
}

// Location is where a finding points in the original spec files.
type Location struct {
	File   string
	Line   int
	Column int
}

// Finding is one place in the spec where a rule is broken.
type Finding struct {
	Rule      Rule
	Location  Location
	Operation string // "GET /orders"; empty when the finding is not about an operation
	Why       string // why it is a risk, in plain words
	Fix       string // how to fix it

	// Element is the spec element a finding without an operation belongs
	// to (a security scheme, a server, an OAuth2 flow, the spec itself), so
	// an x-procyon-ignore written on that element covers it and nothing
	// else. It is compared by identity; formats never read it.
	Element any

	// Also lists the other operations a finding about a shared schema
	// applies to; Operation is the first one.
	Also []string

	// Field is the response field a runtime finding is about, written the
	// way an x-procyon-ignore names it ("reviews.email"), or "" when the
	// finding is about no single field.
	Field string

	// Evidence is what a runtime test sent and got that proves the finding;
	// empty for lint findings.
	Evidence []Exchange
}

// Report is everything one run produced.
type Report struct {
	Findings []Finding
	// Failed is true when at least one finding is at or above the fail
	// threshold.
	Failed bool
	// Ignored are the findings an x-procyon-ignore matched.
	Ignored []IgnoredFinding
	// Notes are things to know that are not findings: expired and unused
	// ignores.
	Notes []Note
	// FailOn is the fail threshold the run used.
	FailOn Severity
	// Matrix is a runtime test's authorization matrix, one row per
	// operation in test order; empty for a lint.
	Matrix []MatrixRow
	// Sources holds the lines of every spec file read, by the same path
	// findings use, so formats can show excerpts without reading files.
	Sources map[string][]string
}

// IgnoredFinding is a finding an ignore matched. It is still reported, and
// never fails the run.
type IgnoredFinding struct {
	Finding Finding
	Reason  string
	Expires string // "2027-01-31", or "" for never
}

// Note is something a run wants the reader to know that is not a finding: an
// ignore that expired, or one that matches nothing. Notes never fail a run.
type Note struct {
	Location Location
	Message  string
}

// Exchange is one request a runtime test sent and what it got: the
// evidence behind a runtime finding. Credentials never appear in it.
type Exchange struct {
	Caller string // "anonymous", "A" or "B"
	Method string
	URL    string // the path and query, as sent: "/notes/1"
	Status int    // 0 when the request got no answer within the timeout
	Body   string // the start of the response body
	Sent   string // the start of the request body, when there was one
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
	NotCalled Outcome = ""          // this caller is not tested on this operation
	Allowed   Outcome = "allowed"   // a 2xx, as expected
	Denied    Outcome = "denied"    // not a 2xx, nor a 5xx
	Failed    Outcome = "error"     // a 5xx: the server failed, which says nothing about who may call it
	Reached   Outcome = "finding"   // a 2xx that is a finding (PRC101, PRC102)
	Public    Outcome = "public"    // x-procyon-public, not called anonymously
	Skipped   Outcome = "skipped"   // could not be called; a note says why
	Unchanged Outcome = "unchanged" // not tested: unchanged since --base-spec
)
