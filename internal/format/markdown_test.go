package format_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/lint"
)

func TestMarkdown(t *testing.T) {
	report := sarifReport()
	// Text from the spec is untrusted: it must not inject links, HTML or
	// break a code span in the job summary.
	report.Ignored[0].Reason = "Internal mirror <img src=x> [click](https://evil.example)\n# Owned www.evil.example me@evil.example"
	report.Findings[0].Operation = "`GET /orders/\n# [x](https://evil.example)"
	// So is what the API answered.
	evil := bola
	evil.Evidence = append([]lint.Exchange{{Caller: "B", Method: "GET", URL: "/orders/1", Status: 200,
		Body: "{\"note\": \"`[x](https://evil.example)` <img src=x>\"}"}}, bola.Evidence...)
	report.Findings = append(report.Findings, evil)
	var got bytes.Buffer
	if err := format.Markdown(&got, report); err != nil {
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
var _ = lint.High

func TestMarkdownAuthorizationMatrix(t *testing.T) {
	report := lint.Report{FailOn: lint.High, Failed: true, Findings: []lint.Finding{bola}, Matrix: []lint.MatrixRow{
		{Operation: "GET /health", Anonymous: lint.Cell{Outcome: lint.Public}},
		{Operation: "GET /orders", A: lint.Cell{Outcome: lint.Allowed, Status: 200}, Anonymous: lint.Cell{Outcome: lint.Denied, Status: 401}},
		{Operation: "GET /orders/{id}", A: lint.Cell{Outcome: lint.Allowed, Status: 200}, B: lint.Cell{Outcome: lint.Denied, Status: 404}, Anonymous: lint.Cell{Outcome: lint.Denied, Status: 401}},
		{Operation: "DELETE /orders/{id}", B: lint.Cell{Outcome: lint.Reached, Status: 204}, Anonymous: lint.Cell{Outcome: lint.Denied, Status: 401}},
		{Operation: "GET /reports/{id}", A: lint.Cell{Outcome: lint.Skipped}, B: lint.Cell{Outcome: lint.Skipped}, Anonymous: lint.Cell{Outcome: lint.Skipped}},
		{Operation: "GET /users/{id}", A: lint.Cell{Outcome: lint.Allowed, Status: 200}, B: lint.Cell{Outcome: lint.Unchanged}, Anonymous: lint.Cell{Outcome: lint.Unchanged}},
	}}
	var got bytes.Buffer
	if err := format.Markdown(&got, report); err != nil {
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
