package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

// runOn runs procyon test against handler, served on loopback for the run,
// with vulnapi's two accounts unless opts sets others.
func runOn(t *testing.T, spec string, handler http.Handler, opts Options) lint.Report {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	opts.BaseURL = srv.URL
	if opts.TokenA == "" && opts.LoginA == nil {
		opts.TokenA = vulnapi.TokenA
	}
	if opts.TokenB == "" && opts.LoginB == nil {
		opts.TokenB = vulnapi.TokenB
	}
	report, err := Run(context.Background(), spec, opts)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// findingKeys lists a report's findings as "PRC102 GET /notes/{id}".
func findingKeys(report lint.Report) []string {
	var keys []string
	for _, f := range report.Findings {
		keys = append(keys, f.Rule.ID+" "+f.Operation)
	}
	return keys
}

// findingsOf lists a report's findings of one rule.
func findingsOf(report lint.Report, rule string) []lint.Finding {
	var found []lint.Finding
	for _, f := range report.Findings {
		if f.Rule.ID == rule {
			found = append(found, f)
		}
	}
	return found
}

// userOf is who a fake API's request comes from: "alice" (A), "bob" (B), or
// "" with no known token.
func userOf(r *http.Request) string {
	return map[string]string{"Bearer " + vulnapi.TokenA: "alice", "Bearer " + vulnapi.TokenB: "bob"}[r.Header.Get("Authorization")]
}
