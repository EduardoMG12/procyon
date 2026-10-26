package lint

import "github.com/EduardoMG12/procyon/internal/report"

// Temporary aliases while the report model moves to internal/report: every
// package switches to it in its own PR, then this file goes.
type (
	Severity       = report.Severity
	Location       = report.Location
	Rule           = report.Rule
	Finding        = report.Finding
	Report         = report.Report
	IgnoredFinding = report.IgnoredFinding
	Note           = report.Note
	Exchange       = report.Exchange
	MatrixRow      = report.MatrixRow
	Cell           = report.Cell
	Outcome        = report.Outcome
)

const (
	Low      = report.Low
	Medium   = report.Medium
	High     = report.High
	Critical = report.Critical

	NotCalled = report.NotCalled
	Allowed   = report.Allowed
	Denied    = report.Denied
	Reached   = report.Reached
	Public    = report.Public
	Skipped   = report.Skipped
	Unchanged = report.Unchanged
)

// ParseSeverity is report.ParseSeverity.
var ParseSeverity = report.ParseSeverity
