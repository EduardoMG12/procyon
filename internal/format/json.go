package format

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf16"

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
	Matrix   []jsonRow     `json:"matrix,omitempty"`
}

// jsonRow is one operation of procyon test's authorization matrix; a
// caller not called on it is absent.
type jsonRow struct {
	Operation string    `json:"operation"`
	A         *jsonCell `json:"a,omitempty"`
	B         *jsonCell `json:"b,omitempty"`
	Anonymous *jsonCell `json:"anonymous,omitempty"`
}

type jsonCell struct {
	Outcome string `json:"outcome"`
	Status  int    `json:"status,omitempty"`
}

func toJSONCell(c report.Cell) *jsonCell {
	if c.Outcome == report.NotCalled {
		return nil
	}
	return &jsonCell{string(c.Outcome), c.Status}
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
	count := severityCounts(rep.Findings)
	out.Summary = jsonSummary{
		Critical: count[report.Critical],
		High:     count[report.High],
		Medium:   count[report.Medium],
		Low:      count[report.Low],
		Ignored:  len(rep.Ignored),
	}
	for _, f := range rep.Findings {
		out.Findings = append(out.Findings, toJSON(f))
	}
	for _, i := range rep.Ignored {
		out.Ignored = append(out.Ignored, jsonIgnored{toJSON(i.Finding), i.Reason, i.Expires})
	}
	for _, n := range rep.Notes {
		out.Notes = append(out.Notes, jsonNote{jsonLoc(n.Location), n.Message})
	}
	for _, row := range rep.Matrix {
		out.Matrix = append(out.Matrix, jsonRow{row.Operation, toJSONCell(row.A), toJSONCell(row.B), toJSONCell(row.Anonymous)})
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := io.WriteString(w, escapeHidden(buf.String()))
	return err
}

// escapeHidden writes the hidden characters of encoded JSON as \u escapes.
// encoding/json escapes C0 only; DEL, C1, bidi controls and invisible
// characters stay raw, and would act on whoever reads the file in a
// terminal or a CI log. Unlike visible, this keeps every value: a script
// decodes the same strings. The only raw control left in encoded JSON is
// the newline of the indentation, outside any string, and it stays.
func escapeHidden(encoded string) string {
	var b strings.Builder
	for _, r := range encoded {
		if r == '\n' || !hidden(r) {
			b.WriteRune(r)
			continue
		}
		// A character beyond U+FFFF is written as a UTF-16 surrogate pair,
		// as JSON requires.
		for _, unit := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u%04x`, unit)
		}
	}
	return b.String()
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
