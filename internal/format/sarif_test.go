package format_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/lint"
)

func sarifReport() lint.Report {
	prc001 := lint.Rule{ID: "PRC001", Title: "Operation has no authentication", Severity: lint.High, OWASP: "API2:2023 Broken Authentication"}
	prc004 := lint.Rule{ID: "PRC004", Title: "Server URL does not use TLS", Severity: lint.High, OWASP: "API8:2023 Security Misconfiguration"}
	return lint.Report{
		FailOn: lint.High,
		Failed: true,
		Findings: []lint.Finding{{
			Rule: prc001, Location: lint.Location{File: filepath.Join(".", "specs", "shop.yaml"), Line: 9, Column: 5},
			Operation: "GET /orders", Why: "Anyone can call it.", Fix: "Add security.",
		}},
		Ignored: []lint.IgnoredFinding{{
			Finding: lint.Finding{Rule: prc004, Location: lint.Location{File: filepath.Join("specs", "shop.yaml"), Line: 6, Column: 12},
				Why: "Unencrypted.", Fix: "Use https."},
			Reason: "Internal mirror",
		}},
		Notes: []lint.Note{{
			Location: lint.Location{File: filepath.Join("specs", "shop.yaml"), Line: 27, Column: 7},
			Message:  "ignore of PRC010 on GET /orders matches no finding; remove it",
		}},
	}
}

func TestSARIF(t *testing.T) {
	var got bytes.Buffer
	if err := format.SARIF(&got, sarifReport(), []lint.Rule{
		{ID: "PRC001", Title: "Operation has no authentication", Severity: lint.High, OWASP: "API2:2023 Broken Authentication"},
		{ID: "PRC004", Title: "Server URL does not use TLS", Severity: lint.High, OWASP: "API8:2023 Security Misconfiguration"},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "report.sarif.golden")
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

// What GitHub code scanning needs from a SARIF file, checked on every
// rule: the official schema cannot be vendored (its license is not an
// open-source one), so these are the requirements that matter.
func TestSARIFMeetsWhatGitHubRequires(t *testing.T) {
	var got bytes.Buffer
	if err := format.SARIF(&got, sarifReport(), lint.Rules()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name == "" {
		t.Fatalf("not a SARIF 2.1.0 log with one run and a tool name: %+v", log)
	}
	var ids []string
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		ids = append(ids, r.ID)
	}
	if len(ids) != len(lint.Rules()) {
		t.Errorf("driver declares %d rules, want all %d", len(ids), len(lint.Rules()))
	}
	for _, r := range log.Runs[0].Results {
		if !slices.Contains(ids, r.RuleID) {
			t.Errorf("result for undeclared rule %q", r.RuleID)
		}
		if !slices.Contains([]string{"error", "warning", "note"}, r.Level) || r.Message.Text == "" {
			t.Errorf("result %s: level %q, message %q", r.RuleID, r.Level, r.Message.Text)
		}
		for _, l := range r.Locations {
			p := l.PhysicalLocation
			if p.ArtifactLocation.URI == "" || p.Region.StartLine < 1 || p.Region.StartColumn < 1 {
				t.Errorf("result %s: bad location %+v", r.RuleID, p)
			}
		}
	}
}
