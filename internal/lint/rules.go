package lint

import (
	"github.com/EduardoMG12/procyon/internal/loader"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// lintRule is one lint rule: what reports show about it, and its check.
type lintRule struct {
	report.Rule
	// check returns the rule's findings; the engine fills in Finding.Rule.
	check func(doc *openapi3.T) []report.Finding
}

// Rules returns every lint rule, in ID order.
func Rules() []report.Rule {
	out := make([]report.Rule, len(rules))
	for i, r := range rules {
		out[i] = r.Rule
	}
	return out
}

// rules is every lint rule, in ID order.
var rules = []lintRule{prc001, prc002, prc003, prc004, prc005, prc006, prc007, prc008, prc009, prc010, prc011}

var prc001 = lintRule{
	Rule: report.Rule{
		ID:       "PRC001",
		Title:    "Operation has no authentication",
		Severity: report.High,
		OWASP:    "API2:2023 Broken Authentication",
	},
	check: func(doc *openapi3.T) []report.Finding {
		var findings []report.Finding
		loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
			if !loader.Unauthenticated(doc, path, op) || loader.PublicReason(op) != "" {
				return
			}
			findings = append(findings, report.Finding{
				Location:  loader.Locate(op.Origin),
				Operation: method + " " + path,
				Why:       "Anyone who can reach the API can call this operation, without proving who they are.",
				Fix:       "Add a security requirement to the operation or to the whole spec.",
			})
		})
		return findings
	},
}

// onePerPlace collects a rule's findings about schema properties. A schema
// shared by several operations is one problem, fixed where it is written:
// one finding at that place, listing every operation that reaches it, so an
// ignore on one of them covers only that one (see report.New).
type onePerPlace struct {
	findings []report.Finding
	at       map[report.Location]int // place -> index in findings
}

func (p *onePerPlace) add(f report.Finding) {
	if i, ok := p.at[f.Location]; ok {
		g := &p.findings[i]
		// Operations are visited one after another, so a repeat (the same
		// schema under two media types) is always the last one added.
		last := g.Operation
		if n := len(g.Also); n > 0 {
			last = g.Also[n-1]
		}
		if last != f.Operation {
			g.Also = append(g.Also, f.Operation)
		}
		return
	}
	if p.at == nil {
		p.at = map[report.Location]int{}
	}
	p.at[f.Location] = len(p.findings)
	p.findings = append(p.findings, f)
}
