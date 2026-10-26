package format_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/report"
)

func TestJSON(t *testing.T) {
	rep := report.Report{
		FailOn: report.High,
		Failed: true,
		Findings: []report.Finding{{
			Rule:      report.Rule{ID: "PRC001", Title: "Operation has no authentication", Severity: report.High, OWASP: "API2:2023 Broken Authentication"},
			Location:  report.Location{File: filepath.Join("specs", "shop.yaml"), Line: 9, Column: 5},
			Operation: "GET /orders",
			Why:       "Anyone can call it.",
			Fix:       "Add security.",
		}, bola},
		Ignored: []report.IgnoredFinding{{
			Finding: report.Finding{
				Rule:     report.Rule{ID: "PRC004", Title: "Server URL does not use TLS", Severity: report.High, OWASP: "API8:2023 Security Misconfiguration"},
				Location: report.Location{File: filepath.Join("specs", "shop.yaml"), Line: 6, Column: 12},
				Why:      "Unencrypted.",
				Fix:      "Use https.",
			},
			Reason:  "Internal mirror",
			Expires: "2027-01-31",
		}},
		Notes: []report.Note{{
			Location: report.Location{File: filepath.Join("specs", "shop.yaml"), Line: 27, Column: 7},
			Message:  "ignore of PRC010 on GET /orders matches no finding; remove it",
		}},
	}
	var got bytes.Buffer
	if err := format.JSON(&got, rep); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "report.json.golden")
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
