package lint_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/report"
)

// today is fixed so expiry is deterministic: after 2026-01-31.
var today = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func TestIgnores(t *testing.T) {
	rep, err := lint.Run(spec("ignores.yaml"), lint.Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	var findings, ignored, notes []string
	for _, f := range rep.Findings {
		findings = append(findings, fmt.Sprintf("%s %s", f.Rule.ID, f.Operation))
	}
	for _, i := range rep.Ignored {
		ignored = append(ignored, fmt.Sprintf("%s %s: %s", i.Finding.Rule.ID, i.Finding.Operation, i.Reason))
	}
	for _, n := range rep.Notes {
		notes = append(notes, n.Message)
	}

	// The expired ignore no longer applies: PRC001 on /reports counts again.
	if !slices.Contains(findings, "PRC001 GET /reports/{id}") {
		t.Errorf("findings %q: want PRC001 on GET /reports/{id} (its ignore expired)", findings)
	}
	// An ignore covers the element it is written on, and nothing else: the
	// second weak scheme and the second plain-text server are still reported.
	for _, w := range []string{"PRC003 ", "PRC004 "} {
		if !slices.Contains(findings, w) {
			t.Errorf("findings %q: want %q still reported (not covered by the other element's ignore)", findings, w)
		}
	}
	wantIgnored := []string{
		"PRC003 : Basic auth is only used by the legacy importer, behind the VPN",
		"PRC004 : Internal mirror, reachable only inside the VPN",
		"PRC001 GET /health: Load balancer health check, returns no data",
		"PRC007 GET /reports/{id}: Report IDs are random UUIDs",
	}
	for _, w := range wantIgnored {
		if !slices.Contains(ignored, w) {
			t.Errorf("ignored %q: missing %q", ignored, w)
		}
	}
	for _, f := range rep.Findings {
		if f.Operation == "GET /health" {
			t.Errorf("finding %s %s should be ignored", f.Rule.ID, f.Operation)
		}
	}
	wantNotes := []string{
		"ignore of PRC001 on GET /reports/{id} expired on 2026-01-31",
		"ignore of PRC010 on GET /reports/{id} matches no finding",
	}
	for _, w := range wantNotes {
		if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, w) }) {
			t.Errorf("notes %q: missing %q", notes, w)
		}
	}
}

// Ignored findings never fail the run: whether it fails depends only on
// the findings left, even when ignored ones are high.
func TestIgnoredFindingsDoNotFail(t *testing.T) {
	rep, err := lint.Run(spec("ignores.yaml"), lint.Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	highIgnored := slices.ContainsFunc(rep.Ignored, func(i report.IgnoredFinding) bool { return i.Finding.Rule.Severity >= report.High })
	if !highIgnored {
		t.Fatal("fixture should ignore at least one high finding")
	}
	highLeft := slices.ContainsFunc(rep.Findings, func(f report.Finding) bool { return f.Rule.Severity >= report.High })
	if rep.Failed != highLeft {
		t.Errorf("Failed = %v, want %v (only findings left decide)", rep.Failed, highLeft)
	}
	rep, err = lint.Run(spec("ignores.yaml"), lint.Options{Today: today, FailOn: report.Critical})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed {
		t.Error("nothing is critical, yet the run failed")
	}
}

// An expiry date lasts until the end of that day where Procyon runs, in any
// time zone.
func TestIgnoreExpiresAtTheEndOfTheDayInAnyTimeZone(t *testing.T) {
	saoPaulo := time.FixedZone("BRT", -3*60*60)
	tokyo := time.FixedZone("JST", 9*60*60)
	for _, tc := range []struct {
		now     time.Time
		expired bool
	}{
		{time.Date(2026, 1, 31, 21, 30, 0, 0, saoPaulo), false}, // still the 31st locally
		{time.Date(2026, 1, 31, 23, 59, 0, 0, saoPaulo), false},
		{time.Date(2026, 2, 1, 0, 0, 0, 0, saoPaulo), true},
		{time.Date(2026, 2, 1, 8, 0, 0, 0, tokyo), true}, // the 1st locally
	} {
		rep, err := lint.Run(spec("ignores.yaml"), lint.Options{Today: tc.now})
		if err != nil {
			t.Fatal(err)
		}
		expired := slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return strings.Contains(n.Message, "expired") })
		if expired != tc.expired {
			t.Errorf("at %s: expired = %v, want %v", tc.now, expired, tc.expired)
		}
	}
}

// A schema shared by two operations, ignored on the one Procyon does not
// visit first: that operation's finding is ignored, the other's is still
// reported, and the ignore is not reported as unused.
func TestIgnoreOnOneOperationOfASharedSchema(t *testing.T) {
	rep, err := lint.Run(spec("prc009-shared-ignore-second.yaml"), lint.Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	var findings, ignored []string
	for _, f := range rep.Findings {
		if f.Rule.ID == "PRC009" {
			findings = append(findings, fmt.Sprintf("%s %s", f.Rule.ID, f.Operation))
		}
	}
	for _, i := range rep.Ignored {
		ignored = append(ignored, fmt.Sprintf("%s %s", i.Finding.Rule.ID, i.Finding.Operation))
	}
	if want := []string{"PRC009 POST /admin/users"}; !slices.Equal(findings, want) {
		t.Errorf("findings = %q, want %q", findings, want)
	}
	if want := []string{"PRC009 POST /register"}; !slices.Equal(ignored, want) {
		t.Errorf("ignored = %q, want %q", ignored, want)
	}
	for _, n := range rep.Notes {
		t.Errorf("unexpected note: %s", n.Message)
	}
}
