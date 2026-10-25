package test

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

const vulnapiSpec = "../vulnapi/openapi.yaml"

// runAgainst tests the notes API, vulnerable or fixed, and returns each
// finding as "rule operation".
func runAgainst(t *testing.T, fixed bool) (lint.Report, []string) {
	t.Helper()
	srv := httptest.NewServer(vulnapi.New(fixed))
	defer srv.Close()
	report, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range report.Findings {
		got = append(got, f.Rule.ID+" "+f.Operation)
	}
	return report, got
}

func TestRunFindsThePlantedVulnerabilities(t *testing.T) {
	report, got := runAgainst(t, false)
	want := []string{"PRC101 GET /notes"}
	if !slices.Equal(got, want) {
		t.Errorf("vulnerable API: findings %q, want %q", got, want)
	}
	if !report.Failed {
		t.Error("a critical finding did not fail the run")
	}
	evidence := report.Findings[0].Evidence
	if len(evidence) != 1 || evidence[0].Caller != "anonymous" || evidence[0].Status != 200 ||
		!strings.HasSuffix(evidence[0].URL, "/notes") || !strings.Contains(evidence[0].Body, `"owner":"alice"`) {
		t.Errorf("evidence = %+v, want the anonymous GET /notes and its 200 with alice's notes", evidence)
	}
}

func TestRunFindsNothingInTheFixedTwin(t *testing.T) {
	report, got := runAgainst(t, true)
	if len(got) != 0 || report.Failed {
		t.Errorf("fixed API: findings %q, failed %v; want none", got, report.Failed)
	}
	// Operations Procyon cannot call yet are visible, never silently passed.
	if len(report.Notes) != 3 {
		t.Errorf("notes = %v, want one per operation on /notes/{id}", report.Notes)
	}
}

func TestRunRefusesAPublicTarget(t *testing.T) {
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://8.8.8.8"})
	if err == nil || !strings.Contains(err.Error(), "not a loopback or private address") {
		t.Errorf("err = %v, want the target refused", err)
	}
}

func TestInTestOrder(t *testing.T) {
	ops := []lint.Operation{
		{Method: "DELETE", Path: "/a"}, {Method: "GET", Path: "/a"}, {Method: "POST", Path: "/a"},
		{Method: "GET", Path: "/b"}, {Method: "PUT", Path: "/b"},
	}
	var got []string
	for _, op := range inTestOrder(ops) {
		got = append(got, op.Method+" "+op.Path)
	}
	want := []string{"GET /a", "GET /b", "POST /a", "PUT /b", "DELETE /a"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %q, want %q", got, want)
	}
}
