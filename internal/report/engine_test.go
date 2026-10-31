package report

import (
	"slices"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	high := Rule{ID: "PRC001", Severity: High}
	low := Rule{ID: "PRC008", Severity: Low}
	findings := []Finding{
		{Rule: low, Location: Location{File: "a.yaml", Line: 9}, Operation: "GET /b"},
		// A shared schema's finding, on two operations: an ignore covers one.
		{Rule: high, Location: Location{File: "a.yaml", Line: 3}, Operation: "GET /a", Also: []string{"GET /c"}},
	}
	ignores := []Ignore{
		{Rule: "PRC001", Reason: "public", Operation: "GET /a"},
		{Rule: "PRC008", Reason: "old", Operation: "GET /b", Expires: "2026-01-31", Until: time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)},
		{Rule: "PRC001", Reason: "stale", Operation: "GET /gone"},
	}
	rep := New(findings, []Note{{Message: "from the caller"}}, ignores, Options{Today: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})

	var got []string
	for _, f := range rep.Findings {
		got = append(got, f.Rule.ID+" "+f.Operation)
	}
	// Sorted by line; the ignore on GET /a leaves GET /c; the expired one
	// covers nothing.
	if want := []string{"PRC001 GET /c", "PRC008 GET /b"}; !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
	if len(rep.Ignored) != 1 || rep.Ignored[0].Finding.Operation != "GET /a" {
		t.Errorf("ignored %+v, want GET /a", rep.Ignored)
	}
	var notes []string
	for _, n := range rep.Notes {
		notes = append(notes, n.Message)
	}
	want := []string{
		"from the caller",
		"ignore of PRC008 on GET /b expired on 2026-01-31; its findings count again",
		"ignore of PRC001 on GET /gone matches no finding; remove it",
	}
	if !slices.Equal(notes, want) {
		t.Errorf("notes %q, want %q", notes, want)
	}
	if rep.FailOn != High || !rep.Failed {
		t.Errorf("fail on %v, failed %v; want the default high, and failed", rep.FailOn, rep.Failed)
	}
}

// An ignore that names a field covers the findings about that field only:
// the shop's own phone is kept, a customer's phone on the same operation
// is still reported.
func TestIgnoreOfOneField(t *testing.T) {
	rule := Rule{ID: "PRC106", Severity: High}
	findings := []Finding{
		{Rule: rule, Operation: "GET /shop", Field: "phone"},
		{Rule: rule, Operation: "GET /shop", Field: "reviews.phone"},
	}
	ignores := []Ignore{{Rule: "PRC106", Reason: "the shop's own", Operation: "GET /shop", Field: "phone"}}
	rep := New(findings, nil, ignores, Options{})
	if len(rep.Findings) != 1 || rep.Findings[0].Field != "reviews.phone" ||
		len(rep.Ignored) != 1 || rep.Ignored[0].Finding.Field != "phone" || len(rep.Notes) != 0 {
		t.Errorf("findings %+v, ignored %+v, notes %v; want reviews.phone reported and phone ignored",
			rep.Findings, rep.Ignored, rep.Notes)
	}
}
