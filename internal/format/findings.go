package format

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/EduardoMG12/procyon/internal/report"
)

// How the formats order, count and locate findings.

// location writes a location as file:line:column, with forward slashes on
// every system, for the terminal and markdown formats.
func location(loc report.Location) string {
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(loc.File), loc.Line, loc.Column)
}

// bySeverity returns a copy of findings, most serious first. The sort is
// stable: within a severity, findings keep the engine's location order.
func bySeverity(findings []report.Finding) []report.Finding {
	sorted := slices.Clone(findings)
	slices.SortStableFunc(sorted, func(a, b report.Finding) int {
		return int(b.Rule.Severity) - int(a.Rule.Severity)
	})
	return sorted
}

// severityCounts counts the findings of each severity, for the summaries.
func severityCounts(findings []report.Finding) map[report.Severity]int {
	count := map[report.Severity]int{}
	for _, f := range findings {
		count[f.Rule.Severity]++
	}
	return count
}
