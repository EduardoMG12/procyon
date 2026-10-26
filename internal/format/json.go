package format

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/EduardoMG12/procyon/internal/report"
)

// The JSON format's shape is a contract with every script that reads it:
// fields are only ever added. A change that removes or renames one bumps
// jsonVersion. docs/json-format.md documents it.
const jsonVersion = 1

type jsonReport struct {
	Version  int           `json:"version"`
	Failed   bool          `json:"failed"`
	FailOn   string        `json:"failOn"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
	Ignored  []jsonIgnored `json:"ignored"`
	Notes    []jsonNote    `json:"notes"`
}

type jsonSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Ignored  int `json:"ignored"`
}

type jsonRule struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	OWASP    string `json:"owasp"`
	Docs     string `json:"docs"`
}

type jsonLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type jsonFinding struct {
	Rule      jsonRule       `json:"rule"`
	Location  jsonLocation   `json:"location"`
	Operation string         `json:"operation,omitempty"`
	Why       string         `json:"why"`
	Fix       string         `json:"fix"`
	Evidence  []jsonExchange `json:"evidence,omitempty"`
}

// jsonExchange is one request behind a runtime finding.
type jsonExchange struct {
	Caller string `json:"caller"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Sent   string `json:"sent,omitempty"`
}

type jsonIgnored struct {
	jsonFinding
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
}

type jsonNote struct {
	Location jsonLocation `json:"location"`
	Message  string       `json:"message"`
}

// JSON writes the whole report as JSON, for scripts and other tools.
func JSON(w io.Writer, rep report.Report) error {
	out := jsonReport{
		Version:  jsonVersion,
		Failed:   rep.Failed,
		FailOn:   rep.FailOn.String(),
		Findings: []jsonFinding{},
		Ignored:  []jsonIgnored{},
		Notes:    []jsonNote{},
	}
	for _, f := range rep.Findings {
		out.Findings = append(out.Findings, toJSON(f))
		switch f.Rule.Severity {
		case report.Critical:
			out.Summary.Critical++
		case report.High:
			out.Summary.High++
		case report.Medium:
			out.Summary.Medium++
		case report.Low:
			out.Summary.Low++
		}
	}
	for _, i := range rep.Ignored {
		out.Ignored = append(out.Ignored, jsonIgnored{toJSON(i.Finding), i.Reason, i.Expires})
	}
	out.Summary.Ignored = len(rep.Ignored)
	for _, n := range rep.Notes {
		out.Notes = append(out.Notes, jsonNote{jsonLoc(n.Location), n.Message})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func toJSON(f report.Finding) jsonFinding {
	return jsonFinding{
		Rule: jsonRule{
			ID: f.Rule.ID, Title: f.Rule.Title, Severity: f.Rule.Severity.String(),
			OWASP: f.Rule.OWASP, Docs: f.Rule.DocsURL(),
		},
		Location:  jsonLoc(f.Location),
		Operation: f.Operation,
		Why:       f.Why,
		Fix:       f.Fix,
		Evidence:  evidenceJSON(f.Evidence),
	}
}

func evidenceJSON(exchanges []report.Exchange) []jsonExchange {
	var out []jsonExchange
	for _, e := range exchanges {
		out = append(out, jsonExchange{e.Caller, e.Method, e.URL, e.Status, e.Body, e.Sent})
	}
	return out
}

func jsonLoc(l report.Location) jsonLocation {
	return jsonLocation{File: filepath.ToSlash(l.File), Line: l.Line, Column: l.Column}
}
