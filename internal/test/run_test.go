package test

import (
	"context"
	"net/http"
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
	report, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, TokenB: vulnapi.TokenB})
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
	want := []string{"PRC101 GET /notes", "PRC102 GET /notes/{id}", "PRC102 PUT /notes/{id}", "PRC102 DELETE /notes/{id}"}
	if !slices.Equal(got, want) {
		t.Errorf("vulnerable API: findings %q, want %q", got, want)
	}
	if !report.Failed {
		t.Error("a critical finding did not fail the run")
	}
	bola := report.Findings[1].Evidence
	if len(bola) != 1 || bola[0].Caller != "B" || !strings.HasSuffix(bola[0].URL, "/notes/1") ||
		strings.Contains(bola[0].URL+bola[0].Body, vulnapi.TokenB) {
		t.Errorf("PRC102 evidence = %+v, want B's GET /notes/1, with no token", bola)
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
	// A's GET /notes showed note IDs, so every operation on /notes/{id} was
	// called: nothing is left untested.
	if len(report.Notes) != 0 {
		t.Errorf("notes = %v, want none", report.Notes)
	}
}

func TestRunRefusesAPublicTarget(t *testing.T) {
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://8.8.8.8", TokenA: "a", TokenB: "b"})
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

func TestRunNeedsBothAccounts(t *testing.T) {
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://127.0.0.1:1", TokenA: "a"})
	if err == nil || !strings.Contains(err.Error(), "PROCYON_USER_B_TOKEN") {
		t.Errorf("err = %v, want it to name PROCYON_USER_B_TOKEN", err)
	}
}

// A 2xx to B is a pass when it does not hold A's object: B's own data, or
// nothing.
func TestPRC102NeedsAsObjectInTheResponse(t *testing.T) {
	for name, answer := range map[string]string{
		"B's own note": `{"id": "3", "owner": "bob"}`,
		"empty list":   `[]`,
		"not JSON":     `ok`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			switch {
			case token == "":
				w.WriteHeader(http.StatusUnauthorized)
			case r.URL.Path == "/notes" && token == "Bearer "+vulnapi.TokenA:
				w.Write([]byte(`[{"id": "1", "owner": "alice"}]`))
			case r.URL.Path == "/notes":
				w.Write([]byte(`[{"id": "3", "owner": "bob"}]`))
			case token == "Bearer "+vulnapi.TokenB:
				w.Write([]byte(answer))
			}
		}))
		report, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, TokenB: vulnapi.TokenB})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range report.Findings {
			if f.Rule.ID == "PRC102" {
				t.Errorf("%s: PRC102 on %s, want none", name, f.Operation)
			}
		}
	}
}

// A write that answers 2xx to B but leaves A's object as it was is a pass:
// A reads it before and after.
func TestPRC102WritesAreConfirmedByA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		switch {
		case token == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "GET" && r.URL.Path == "/notes" && token == "Bearer "+vulnapi.TokenB:
			w.Write([]byte(`[{"id": "3", "owner": "bob"}]`))
		case r.Method == "GET" && r.URL.Path == "/notes/3":
			w.Write([]byte(`{"id": "3", "owner": "bob"}`))
		case r.Method == "GET" && token == "Bearer "+vulnapi.TokenB:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET": // A's own notes, never changed
			w.Write([]byte(`[{"id": "1", "owner": "alice"}]`))
		default: // B's PUT and DELETE say yes and do nothing
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	report, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, TokenB: vulnapi.TokenB})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Rule.ID == "PRC102" {
			t.Errorf("PRC102 on %s, want none: A's note never changed", f.Operation)
		}
	}
}
