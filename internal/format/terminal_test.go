package format_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files with the current output")

// shop is the spec every report below points into. Built with filepath.Join
// so that on Windows it has backslashes, and the output must still show
// forward slashes.
var shop = filepath.Join("specs", "shop.yaml")

var shopLines = []string{
	"openapi: 3.0.3",
	"info:",
	"  title: Shop",
	"  version: 1.0.0",
	"servers:",
	"  - url: http://api.example.com",
	"paths:",
	"  /orders:",
	"    get:",
	"      responses:",
	"        \"200\":",
	"          description: Orders",
}

var (
	prc001 = report.Rule{ID: "PRC001", Title: "Operation has no authentication", Severity: report.High}
	prc004 = report.Rule{ID: "PRC004", Title: "Server URL does not use TLS", Severity: report.Medium}
	prc008 = report.Rule{ID: "PRC008", Title: "Unbounded input or output", Severity: report.Low}
)

// bola is a runtime finding: it carries evidence.
var bola = report.Finding{
	Rule:      report.Rule{ID: "PRC102", Title: "Another account reached A's object", Severity: report.Critical, OWASP: "API1:2023 Broken Object Level Authorization"},
	Location:  report.Location{File: shop, Line: 9, Column: 5},
	Operation: "DELETE /orders/{id}",
	Why:       "B deleted A's order.",
	Fix:       "Check the owner.",
	Evidence: []report.Exchange{
		{Caller: "B", Method: "DELETE", URL: "/orders/1", Status: 204, Sent: `{"reason": "x"}`},
		{Caller: "A", Method: "GET", URL: "/orders/1", Status: 404, Body: "{\n  \"error\": \"no such order\"\n}"},
	},
}

func TestTerminal(t *testing.T) {
	sources := map[string][]string{shop: shopLines}
	noAuth := report.Finding{
		Rule:      prc001,
		Location:  report.Location{File: shop, Line: 9, Column: 5},
		Operation: "GET /orders",
		Why:       "Anyone who can reach the API can call this operation, without proving who they are.",
		Fix:       "Add a security requirement to the operation or to the whole spec.",
	}
	tests := []struct {
		golden string
		rep    report.Report
		color  bool
	}{
		{"no-findings", report.Report{FailOn: report.High}, false},
		{"one-finding", report.Report{FailOn: report.High, Failed: true, Findings: []report.Finding{noAuth}, Sources: sources}, false},
		{"one-finding-color", report.Report{FailOn: report.High, Failed: true, Findings: []report.Finding{noAuth}, Sources: sources}, true},
		{"severities", report.Report{FailOn: report.Medium, Failed: true, Sources: sources, Findings: []report.Finding{
			// In location order, as the engine returns them; the format
			// groups them by severity.
			{Rule: prc008, Location: report.Location{File: shop, Line: 1, Column: 1},
				Why: "Nothing limits how big a request can be.", Fix: "Add maxLength."},
			{Rule: prc004, Location: report.Location{File: shop, Line: 6, Column: 12},
				Why: "Traffic to this server is sent unencrypted, so anyone on the network path can read or change it, including credentials.",
				Fix: "Use an https:// URL."},
			noAuth,
			{Rule: prc008, Location: report.Location{File: shop, Line: 12, Column: 11},
				Why: "Nothing limits how big a response can be.", Fix: "Add paging."},
		}}, false},
	}
	// A minified JSON spec: everything on line 1. The excerpt must show a
	// window around the column, not the whole file once per finding.
	minified := filepath.Join("specs", "min.json")
	long := `{"openapi":"3.0.3","info":{"title":"Shop","version":"1.0.0"},"paths":{"/orders":{"get":{"responses":{"200":{"description":"Orders"}}},"post":{"responses":{"201":{"description":"Created"}}}},"/users":{"get":{"responses":{"200":{"description":"Users"}}}}}}`
	tests = append(tests, struct {
		golden string
		rep    report.Report
		color  bool
	}{"long-line", report.Report{FailOn: report.High, Failed: true,
		Sources: map[string][]string{minified: {long}},
		Findings: []report.Finding{{Rule: prc001, Location: report.Location{File: minified, Line: 1, Column: 150},
			Operation: "POST /orders", Why: "Anyone can call it.", Fix: "Add security."}},
	}, false})

	// A runtime finding shows the requests that prove it.
	tests = append(tests, struct {
		golden string
		rep    report.Report
		color  bool
	}{"runtime-evidence", report.Report{FailOn: report.High, Failed: true, Sources: sources, Findings: []report.Finding{bola}}, false})

	// Ignored findings and notes stay visible, in their own sections.
	tests = append(tests, struct {
		golden string
		rep    report.Report
		color  bool
	}{"ignored-and-notes", report.Report{FailOn: report.High, Sources: sources,
		Ignored: []report.IgnoredFinding{
			{Finding: noAuth, Reason: "Load balancer health check, returns no data"},
			{Finding: report.Finding{Rule: prc004, Location: report.Location{File: shop, Line: 6, Column: 12}}, Reason: "Internal mirror", Expires: "2027-01-31"},
		},
		Notes: []report.Note{
			{Location: report.Location{File: shop, Line: 9, Column: 5}, Message: "ignore of PRC010 on GET /orders matches no finding; remove it"},
		},
	}, false})

	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			var got bytes.Buffer
			if err := format.Terminal(&got, tt.rep, format.TerminalOptions{Color: tt.color}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "terminal-"+tt.golden+".golden")
			if *update {
				if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/format -update to create it)", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got.Bytes(), want)
			}
		})
	}
}
