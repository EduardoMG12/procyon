package lint_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// today is fixed so expiry is deterministic: after 2026-01-31.
var today = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func TestIgnores(t *testing.T) {
	report, err := lint.Run(spec("ignores.yaml"), lint.Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	var findings, ignored, notes []string
	for _, f := range report.Findings {
		findings = append(findings, fmt.Sprintf("%s %s", f.Rule.ID, f.Operation))
	}
	for _, i := range report.Ignored {
		ignored = append(ignored, fmt.Sprintf("%s %s: %s", i.Finding.Rule.ID, i.Finding.Operation, i.Reason))
	}
	for _, n := range report.Notes {
		notes = append(notes, n.Message)
	}

	// The expired ignore no longer applies: PRC001 on /reports counts again.
	if !slices.Contains(findings, "PRC001 GET /reports/{id}") {
		t.Errorf("findings %q: want PRC001 on GET /reports/{id} (its ignore expired)", findings)
	}
	wantIgnored := []string{
		"PRC003 : Basic auth is only used by the legacy importer, behind the VPN",
		"PRC001 GET /health: Load balancer health check, returns no data",
		"PRC007 GET /reports/{id}: Report IDs are random UUIDs",
	}
	for _, w := range wantIgnored {
		if !slices.Contains(ignored, w) {
			t.Errorf("ignored %q: missing %q", ignored, w)
		}
	}
	for _, f := range report.Findings {
		if f.Rule.ID == "PRC003" || f.Operation == "GET /health" {
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

// Ignored findings never fail the run.
func TestIgnoredFindingsDoNotFail(t *testing.T) {
	report, err := lint.Run(spec("ignores.yaml"), lint.Options{Today: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Rule.Severity >= lint.High {
			t.Fatalf("high finding %s %s left; everything high is ignored before 2026-01-31", f.Rule.ID, f.Operation)
		}
	}
	if report.Failed {
		t.Error("the run failed although every high finding is ignored")
	}
}
