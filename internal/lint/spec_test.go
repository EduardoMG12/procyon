package lint

import (
	"slices"
	"strings"
	"testing"
)

func TestLoadListsOperationsInOrder(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, op := range spec.Operations() {
		public := ""
		if op.Public {
			public = " public"
		}
		got = append(got, op.Method+" "+op.Path+public)
	}
	want := []string{
		"GET /health public",
		"GET /me",
		"GET /notes",
		"POST /notes",
		"DELETE /notes/{id}",
		"GET /notes/{id}",
		"PUT /notes/{id}",
	}
	if !slices.Equal(got, want) {
		t.Errorf("operations = %q, want %q", got, want)
	}
	health := spec.Operations()[0]
	if health.Location.Line != 63 || !strings.HasSuffix(health.Location.File, "openapi.yaml") {
		t.Errorf("GET /health location = %+v, want openapi.yaml line 63", health.Location)
	}
	if len(spec.Sources()[health.Location.File]) == 0 {
		t.Error("Sources has no lines for the spec")
	}
}

func TestLoadRefusesWhatRunRefuses(t *testing.T) {
	for _, name := range []string{"invalid-yaml.yaml", "ignore-no-reason.yaml", "ref-remote.yaml"} {
		if _, err := Load("../../testdata/specs/"+name, Options{}); err == nil {
			t.Errorf("Load(%s) succeeded, want the error Run gives", name)
		}
	}
}

// Each kind of run applies the ignores of its own rules and never calls the
// other kind's unused.
func TestIgnoresOfLintAndRuntimeRulesStayApart(t *testing.T) {
	path := "../../testdata/specs/runtime-ignores.yaml"
	report, err := Run(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Ignored) != 1 || report.Ignored[0].Finding.Rule.ID != "PRC001" || len(report.Notes) != 0 {
		t.Errorf("lint: ignored %v, notes %v; want PRC001 ignored and no notes", report.Ignored, report.Notes)
	}

	spec, err := Load(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	op := spec.Operations()[0]
	finding := Finding{Rule: RuntimeRule("PRC101"), Location: op.Location, Operation: op.Method + " " + op.Path}
	report = spec.Finish([]Finding{finding}, nil, Options{})
	if len(report.Findings) != 0 || len(report.Ignored) != 1 || len(report.Notes) != 0 || report.Failed {
		t.Errorf("runtime: findings %v, ignored %v, notes %v, failed %v; want PRC101 ignored, no notes, not failed",
			report.Findings, report.Ignored, report.Notes, report.Failed)
	}

	report = spec.Finish([]Finding{{Rule: RuntimeRule("PRC101"), Operation: "GET /other"}}, nil, Options{})
	if len(report.Findings) != 1 || !report.Failed {
		t.Errorf("an unignored critical finding: findings %v, failed %v; want it kept and the run failed", report.Findings, report.Failed)
	}
}
