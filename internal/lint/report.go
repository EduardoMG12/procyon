package lint

import "fmt"

// Severity is how serious a finding is. The order matters: a higher value is
// more serious, which is how the fail threshold compares them.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// ParseSeverity reads a severity name as written in flags and config.
func ParseSeverity(name string) (Severity, error) {
	for s := Low; s <= Critical; s++ {
		if s.String() == name {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (use critical, high, medium, low)", name)
}

// Location is where a finding points in the original spec files.
type Location struct {
	File   string
	Line   int
	Column int
}

// Finding is one place in the spec where a rule is broken.
type Finding struct {
	Rule      Rule
	Location  Location
	Operation string // "GET /orders"; empty when the finding is not about an operation
	Why       string // why it is a risk, in plain words
	Fix       string // how to fix it

	// about is the spec element a finding without an operation belongs to
	// (a security scheme, a server, an OAuth2 flow, the spec itself), so an
	// x-procyon-ignore written on that element covers it and nothing else.
	about any

	// also lists the other operations a finding about a shared schema
	// applies to (see onePerPlace); Operation is the first one.
	also []string
}

// Report is everything one run produced.
type Report struct {
	Findings []Finding
	// Failed is true when at least one finding is at or above the fail
	// threshold.
	Failed bool
	// Ignored are the findings an x-procyon-ignore matched.
	Ignored []IgnoredFinding
	// Notes are things to know that are not findings: expired and unused
	// ignores.
	Notes []Note
	// FailOn is the fail threshold the run used.
	FailOn Severity
	// Sources holds the lines of every spec file read, by the same path
	// findings use, so formats can show excerpts without reading files.
	Sources map[string][]string
}
