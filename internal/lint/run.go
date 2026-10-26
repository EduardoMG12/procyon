package lint

import (
	"fmt"
	"time"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// Options control a run.
type Options struct {
	// FailOn is the fail threshold: the lowest severity that fails the run.
	// Zero means the default, High.
	FailOn report.Severity
	// RefRoot is the directory $refs may read files from. Empty means the
	// spec's own directory. A monorepo whose specs share files from a
	// sibling folder sets it to the repository root. It must contain the
	// spec, and it may not be the file system's root or the home directory.
	RefRoot string
	// Today decides whether an ignore has expired. Zero means now.
	Today time.Time
}

// Run lints the spec at path.
func Run(path string, opts Options) (report.Report, error) {
	spec, err := loader.Load(path, loader.Options{RefRoot: opts.RefRoot, KnownRule: KnownRule})
	if err != nil {
		return report.Report{}, err
	}
	// Identical findings are one finding: a converted Swagger 2.0 spec copies
	// an element once per media type. Findings that differ only in their
	// operation or reason stay apart, so an ignore on one operation never
	// hides another's.
	seen := map[string]bool{}
	var findings []report.Finding
	for _, rule := range rules {
		for _, f := range rule.check(spec.Doc()) {
			f.Rule = rule.Rule
			f.Location = spec.AsGiven(f.Location)
			key := fmt.Sprintf("%s %s:%d:%d %s %s", rule.ID, f.Location.File, f.Location.Line, f.Location.Column, f.Operation, f.Why)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, f)
		}
	}
	rep := report.New(findings, nil, report.IgnoresOf(spec.Ignores(), Rules()), report.Options{FailOn: opts.FailOn, Today: opts.Today})
	rep.Sources = spec.Sources()
	return rep, nil
}
