package lint

import (
	"fmt"
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
		"POST /login public",
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

func TestOperationCredentials(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-credentials.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/default":       "header Authorization Bearer ",
		"/basic":         "header Authorization Basic ",
		"/key":           "header X-API-Key ",
		"/cookie":        "cookie session ",
		"/oauth":         "header Authorization Bearer ",
		"/both-then-key": "header X-API-Key ", // two schemes at once cannot be filled with one token
		"/mtls":          "none",
		"/none":          "none",
		"/param":         "header x-access-token ",
	}
	for _, op := range spec.Operations() {
		got := "none"
		if c := op.Credential; c != nil {
			got = c.In + " " + c.Name + " " + c.Prefix
		}
		if got != want[op.Path] {
			t.Errorf("%s credential = %q, want %q", op.Path, got, want[op.Path])
		}
	}
}

func TestOperationExampleBodies(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		want, needs := "", false
		if op.Path == "/login" {
			want, needs = "", true // a schema with no example
		} else if op.Method == "POST" || op.Method == "PUT" {
			want, needs = `{"body":"bread, coffee","title":"Shopping list"}`, true
		}
		if string(op.Body) != want || op.NeedsBody != needs {
			t.Errorf("%s %s: body %s, needs %v; want %s, %v", op.Method, op.Path, op.Body, op.NeedsBody, want, needs)
		}
	}
}

func TestOperationBodyFields(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		if op.Method != "POST" || op.Path != "/notes" {
			continue
		}
		var got []string
		for _, f := range op.Fields {
			max := "none"
			if f.MaxLength != nil {
				max = fmt.Sprint(*f.MaxLength)
			}
			got = append(got, fmt.Sprintf("%s %v required=%v max=%s", f.Name, f.Types, f.Required, max))
		}
		want := []string{"body [string] required=false max=10000", "title [string] required=true max=100"}
		if !slices.Equal(got, want) {
			t.Errorf("fields = %q, want %q", got, want)
		}
	}
}

// A runtime finding about no operation (PRC105) is covered by an ignore at
// the spec's root.
func TestRootIgnoreCoversARuntimeFindingAboutTheSpec(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-root-ignore.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	report := spec.Finish([]Finding{{Rule: RuntimeRule("PRC105"), Location: Location{Line: 1, Column: 1}}}, nil, Options{})
	if len(report.Findings) != 0 || len(report.Ignored) != 1 {
		t.Errorf("findings %v, ignored %v; want PRC105 ignored", report.Findings, report.Ignored)
	}
}

func TestExampleBodyFromPropertyExamples(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-vampi-like.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		switch op.Method + " " + op.Path {
		case "PUT /users/{username}/password":
			if string(op.Body) != `{"password":"new-password"}` || !op.NeedsAuth {
				t.Errorf("password body %s, needs auth %v", op.Body, op.NeedsAuth)
			}
		case "GET /users":
			if op.NeedsAuth {
				t.Error("GET /users has no security, NeedsAuth is true")
			}
		}
	}
}
