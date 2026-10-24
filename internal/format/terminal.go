// Package format renders a report. It never decides what is a finding.
package format

import (
	"fmt"
	"io"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// Terminal writes the report for a person reading a terminal or a CI log.
func Terminal(w io.Writer, report lint.Report) error {
	if len(report.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	for _, f := range report.Findings {
		loc := fmt.Sprintf("%s:%d:%d", f.Location.File, f.Location.Line, f.Location.Column)
		_, err := fmt.Fprintf(w, "%-6s %s  %s\n       %s  %s\n       Why:  %s\n       Fix:  %s\n       More: %s\n\n",
			f.Rule.Severity, f.Rule.ID, f.Rule.Title,
			loc, f.Operation,
			f.Why, f.Fix, f.Rule.DocsURL())
		if err != nil {
			return err
		}
	}
	return nil
}
