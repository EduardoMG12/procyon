// Package format renders a report. It never decides what is a finding.
package format

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"
)

// TerminalOptions control the terminal format.
type TerminalOptions struct {
	// Color adds ANSI colours. The caller decides: on for a terminal, off
	// for a pipe, a file or when NO_COLOR is set.
	Color bool
}

const (
	indent       = "        " // under the rule ID in a finding's header
	labelWidth   = 6          // "Why:  ", "Fix:  "
	lineWidth    = 80
	contextLines = 2   // spec lines shown above and below a finding
	excerptWidth = 100 // longest spec line shown whole
	excerptLead  = 30  // characters kept before the column in a long line

	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	red   = "\x1b[1;31m"
	green = "\x1b[1;32m"
)

var severityColor = map[report.Severity]string{
	report.Critical: "\x1b[1;35m",
	report.High:     red,
	report.Medium:   "\x1b[1;33m",
	report.Low:      "\x1b[1;36m",
}

// Terminal writes the report for a person reading a terminal or a CI log:
// most serious findings first, each with the spec lines around it, then a
// one-line summary.
func Terminal(w io.Writer, rep report.Report, opts TerminalOptions) error {
	t := terminal{opts: opts}
	findings := slices.Clone(rep.Findings)
	// Stable: within a severity, findings keep the engine's location order.
	slices.SortStableFunc(findings, func(a, b report.Finding) int {
		return int(b.Rule.Severity) - int(a.Rule.Severity)
	})
	if len(findings) == 0 {
		t.line("No findings.")
		t.line("")
	}
	for _, f := range findings {
		t.finding(f, rep.Sources[f.Location.File])
	}
	t.ignored(rep.Ignored)
	t.notes(rep.Notes)
	t.summary(rep)
	_, err := io.WriteString(w, t.b.String())
	return err
}

type terminal struct {
	opts TerminalOptions
	b    strings.Builder
}

func (t *terminal) line(s string) {
	t.b.WriteString(s)
	t.b.WriteByte('\n')
}

func (t *terminal) paint(color, s string) string {
	if !t.opts.Color {
		return s
	}
	return color + s + reset
}

func (t *terminal) finding(f report.Finding, source []string) {
	// Padded to the indent, plus a space for CRITICAL, the one label as
	// long as the indent.
	label := fmt.Sprintf("%-7s ", strings.ToUpper(f.Rule.Severity.String()))
	t.line(t.paint(severityColor[f.Rule.Severity], label) + f.Rule.ID + "  " + f.Rule.Title)

	loc := location(f.Location)
	if f.Operation != "" {
		loc += "  " + f.Operation
	}
	t.line(indent + loc)
	t.line("")

	if t.excerpt(source, f.Location.Line, f.Location.Column) {
		t.line("")
	}
	t.labelled("Why:", f.Why)
	t.labelled("Fix:", f.Fix)
	t.evidence(f.Evidence)
	t.line(indent + "More: " + f.Rule.DocsURL())
	t.line("")
}

// excerpt prints the spec lines around line, marking it. It reports whether
// it printed anything: a location outside the known source prints nothing.
func (t *terminal) excerpt(source []string, line, column int) bool {
	if line < 1 || line > len(source) {
		return false
	}
	first := max(1, line-contextLines)
	last := min(len(source), line+contextLines)
	width := len(strconv.Itoa(last))
	for n := first; n <= last; n++ {
		mark := "  "
		if n == line {
			mark = "> "
		}
		s := fmt.Sprintf("%s%s%*d | %s", indent, mark, width, n, window(source[n-1], column))
		if n == line {
			s = t.paint(bold, s)
		}
		t.line(s)
	}
	return true
}

// labelled prints text after a label, wrapped to lineWidth, continuation
// lines aligned under the text.
func (t *terminal) labelled(label, text string) {
	prefix := indent + fmt.Sprintf("%-*s", labelWidth, label)
	for _, l := range wrap(text, lineWidth-len(prefix)) {
		t.line(prefix + l)
		prefix = strings.Repeat(" ", len(prefix))
	}
}

// evidence prints the requests that prove a runtime finding: who sent
// what, the status, and the start of the body on one line.
func (t *terminal) evidence(exchanges []report.Exchange) {
	if len(exchanges) == 0 {
		return
	}
	t.line(indent + "Proof:")
	for _, e := range exchanges {
		t.line(indent + "  " + exchangeLine(e))
		if sent := flatten(e.Sent); sent != "" {
			t.line(indent + "    sent " + window(sent, 0))
		}
		if body := flatten(e.Body); body != "" {
			t.line(indent + "    " + window(body, 0))
		}
	}
}

// ignored lists the findings an x-procyon-ignore matched, each with its
// reason: exceptions stay visible on every run.
func (t *terminal) ignored(ignored []report.IgnoredFinding) {
	if len(ignored) == 0 {
		return
	}
	t.line(fmt.Sprintf("Ignored (%d)", len(ignored)))
	for _, i := range ignored {
		line := indent + i.Finding.Rule.ID + "  " + location(i.Finding.Location)
		if i.Finding.Operation != "" {
			line += "  " + i.Finding.Operation
		}
		if i.Expires != "" {
			line += "  (until " + i.Expires + ")"
		}
		t.line(line)
		t.line(indent + indent + i.Reason)
	}
	t.line("")
}

// notes lists what the reader should know that is not a finding.
func (t *terminal) notes(notes []report.Note) {
	if len(notes) == 0 {
		return
	}
	t.line(fmt.Sprintf("Notes (%d)", len(notes)))
	for _, n := range notes {
		t.line(indent + location(n.Location) + "  " + n.Message)
	}
	t.line("")
}

func location(loc report.Location) string {
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(loc.File), loc.Line, loc.Column)
}

func (t *terminal) summary(rep report.Report) {
	count := map[report.Severity]int{}
	for _, f := range rep.Findings {
		count[f.Rule.Severity]++
	}
	verdict := t.paint(green, "PASSED")
	if rep.Failed {
		verdict = t.paint(red, "FAILED")
	}
	counts := fmt.Sprintf("%d high · %d medium · %d low · %d ignored",
		count[report.High], count[report.Medium], count[report.Low], len(rep.Ignored))
	if count[report.Critical] > 0 {
		counts = fmt.Sprintf("%d critical · %s", count[report.Critical], counts)
	}
	t.line(fmt.Sprintf("%s  %s  (fails at: %s)", verdict, counts, rep.FailOn))
}

// wrap splits text into lines of at most width characters, breaking between
// words. A word longer than width gets a line of its own.
func wrap(text string, width int) []string {
	var lines []string
	var current string
	for _, word := range strings.Fields(text) {
		switch {
		case current == "":
			current = word
		case len(current)+1+len(word) <= width:
			current += " " + word
		default:
			lines = append(lines, current)
			current = word
		}
	}
	return append(lines, current)
}

// window cuts a long line (a minified JSON spec is one line) to excerptWidth
// characters around column, marking the cut ends with "…". Shorter lines are
// returned whole.
func window(line string, column int) string {
	runes := []rune(line)
	if len(runes) <= excerptWidth {
		return line
	}
	start := max(0, column-1-excerptLead)
	end := min(len(runes), start+excerptWidth)
	start = max(0, end-excerptWidth)
	cut := string(runes[start:end])
	if start > 0 {
		cut = "…" + cut
	}
	if end < len(runes) {
		cut += "…"
	}
	return cut
}
