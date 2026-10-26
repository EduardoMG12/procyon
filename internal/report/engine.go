package report

import (
	"cmp"
	"fmt"
	"slices"
	"time"
)

// Ignore is one x-procyon-ignore entry, as read from a spec: it stops one
// rule from failing the run on one element, with a reason.
type Ignore struct {
	Rule     string
	Reason   string
	Expires  string    // as written, or "" for never
	Until    time.Time // the expiry date (its day, month and year only)
	Location Location  // where the ignore is written, for notes

	// Operation is the operation the ignore is written on ("GET /orders"),
	// or "" when it is written on another element, listed in Elements (a
	// security scheme, a server, an OAuth2 flow, the spec's root) and named
	// by Where in notes.
	Operation string
	Elements  []any
	Where     string
}

// on names where the ignore lives, for notes.
func (ig Ignore) on() string {
	if ig.Operation != "" {
		return ig.Operation
	}
	return ig.Where
}

// covers reports whether the ignore is written on the element f is about.
func (ig Ignore) covers(f Finding) bool {
	if ig.Rule != f.Rule.ID {
		return false
	}
	if ig.Operation != "" {
		return ig.Operation == f.Operation
	}
	return f.Element != nil && slices.Contains(ig.Elements, f.Element)
}

// expired reports whether the ignore has ended by today. It lasts until the
// end of its date where Procyon runs, so the same spec gives the same
// verdict all day in any time zone.
func (ig Ignore) expired(today time.Time) bool {
	if ig.Until.IsZero() {
		return false
	}
	y, m, d := ig.Until.Date()
	return !today.Before(time.Date(y, m, d+1, 0, 0, 0, 0, today.Location()))
}

// IgnoresOf keeps the ignores of the given rules, so a lint never calls an
// ignore of a runtime rule unused, and a runtime test never calls an ignore
// of a lint rule unused.
func IgnoresOf(ignores []Ignore, rules []Rule) []Ignore {
	var kept []Ignore
	for _, ig := range ignores {
		if slices.ContainsFunc(rules, func(r Rule) bool { return r.ID == ig.Rule }) {
			kept = append(kept, ig)
		}
	}
	return kept
}

// Options control how findings become a report.
type Options struct {
	// FailOn is the fail threshold. Zero means High.
	FailOn Severity
	// Today decides whether an ignore has expired. Zero means now.
	Today time.Time
}

// New turns a run's findings and notes into a report: findings sorted by
// where they point, those an ignore matches moved to Ignored, notes added
// for expired and unused ignores, and the fail threshold checked. Lint and
// runtime runs both end here, so they treat ignores and severities alike.
// The caller sets Sources and Matrix.
func New(findings []Finding, notes []Note, ignores []Ignore, opts Options) Report {
	rep := Report{FailOn: cmp.Or(opts.FailOn, High)}
	today := opts.Today
	if today.IsZero() {
		today = time.Now()
	}
	sortFindings(findings)

	used := make([]bool, len(ignores))
	for _, f := range findings {
		// A finding about a shared schema is checked operation by
		// operation: an ignore on one covers that one only, and the finding
		// is gone only when every operation is ignored.
		var left []string
		for _, op := range append([]string{f.Operation}, f.Also...) {
			one := f
			one.Operation, one.Also = op, nil
			i := slices.IndexFunc(ignores, func(ig Ignore) bool { return ig.covers(one) && !ig.expired(today) })
			if i < 0 {
				left = append(left, op)
				continue
			}
			used[i] = true
			rep.Ignored = append(rep.Ignored, IgnoredFinding{Finding: one, Reason: ignores[i].Reason, Expires: ignores[i].Expires})
		}
		if len(left) > 0 {
			f.Operation, f.Also = left[0], left[1:]
			rep.Findings = append(rep.Findings, f)
		}
	}

	rep.Notes = slices.Clone(notes)
	for i, ig := range ignores {
		switch {
		case ig.expired(today):
			rep.Notes = append(rep.Notes, Note{Location: ig.Location,
				Message: fmt.Sprintf("ignore of %s on %s expired on %s; its findings count again", ig.Rule, ig.on(), ig.Expires)})
		case !used[i]:
			rep.Notes = append(rep.Notes, Note{Location: ig.Location,
				Message: fmt.Sprintf("ignore of %s on %s matches no finding; remove it", ig.Rule, ig.on())})
		}
	}
	rep.Failed = slices.ContainsFunc(rep.Findings, func(f Finding) bool { return f.Rule.Severity >= rep.FailOn })
	return rep
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
