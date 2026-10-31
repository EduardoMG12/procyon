package format_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/report"
)

func TestMarkdown(t *testing.T) {
	rep := sarifReport()
	// Text from the spec is untrusted: it must not inject links, HTML or
	// break a code span in the job summary.
	rep.Ignored[0].Reason = "Internal mirror <img src=x> [click](https://evil.example)\n# Owned www.evil.example me@evil.example"
	rep.Findings[0].Operation = "`GET /orders/\n# [x](https://evil.example)"
	// So is what the API answered.
	evil := bola
	evil.Evidence = append([]report.Exchange{{Caller: "B", Method: "GET", URL: "/orders/1", Status: 200,
		Body: "{\"note\": \"`[x](https://evil.example)` <img src=x>\"}"}}, bola.Evidence...)
	rep.Findings = append(rep.Findings, evil)
	var got bytes.Buffer
	if err := format.Markdown(&got, rep); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "report.md.golden")
	if *update {
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got.Bytes(), want)
	}
}

// Ensure the import of lint is used even if the helper above changes.
var _ = report.High

func TestMarkdownAuthorizationMatrix(t *testing.T) {
	rep := report.Report{FailOn: report.High, Failed: true, Findings: []report.Finding{bola}, Matrix: []report.MatrixRow{
		{Operation: "GET /health", Anonymous: report.Cell{Outcome: report.Public}},
		{Operation: "GET /orders", A: report.Cell{Outcome: report.Allowed, Status: 200}, Anonymous: report.Cell{Outcome: report.Denied, Status: 401}},
		{Operation: "GET /orders/{id}", A: report.Cell{Outcome: report.Allowed, Status: 200}, B: report.Cell{Outcome: report.Denied, Status: 404}, Anonymous: report.Cell{Outcome: report.Denied, Status: 401}},
		{Operation: "DELETE /orders/{id}", B: report.Cell{Outcome: report.Reached, Status: 204}, Anonymous: report.Cell{Outcome: report.Denied, Status: 401}},
		{Operation: "POST /orders", A: report.Cell{Outcome: report.ServerError, Status: 500}, Anonymous: report.Cell{Outcome: report.Denied, Status: 401}},
		{Operation: "GET /reports/{id}", A: report.Cell{Outcome: report.Skipped}, B: report.Cell{Outcome: report.Skipped}, Anonymous: report.Cell{Outcome: report.Skipped}},
		{Operation: "GET /users/{id}", A: report.Cell{Outcome: report.Allowed, Status: 200}, B: report.Cell{Outcome: report.Unchanged}, Anonymous: report.Cell{Outcome: report.Unchanged}},
		{Operation: "GET /a|b", A: report.Cell{Outcome: report.Allowed, Status: 200}}, // a | must not split the row
	}}
	var got bytes.Buffer
	if err := format.Markdown(&got, rep); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "matrix.md.golden")
	if *update {
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got.Bytes(), want)
	}
}
