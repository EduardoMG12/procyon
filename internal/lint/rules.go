package lint

import (
	"slices"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Rule is one security check.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	OWASP    string // OWASP API Security Top 10 (2023) category
	// check returns the rule's findings; the engine fills in Finding.Rule.
	check func(doc *openapi3.T) []Finding
}

// DocsURL is the page that explains the rule.
func (r Rule) DocsURL() string {
	return "https://github.com/EduardoMG12/procyon/blob/main/docs/rules/" + r.ID + ".md"
}

// Rules returns every rule Procyon runs, in ID order.
func Rules() []Rule {
	return slices.Clone(rules)
}

// rules is every rule Procyon runs, in ID order.
var rules = []Rule{prc001, prc002, prc003, prc004, prc005, prc006, prc007, prc008, prc009, prc010, prc011}

var prc001 = Rule{
	ID:       "PRC001",
	Title:    "Operation has no authentication",
	Severity: High,
	OWASP:    "API2:2023 Broken Authentication",
	check: func(doc *openapi3.T) []Finding {
		var findings []Finding
		forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
			if !unauthenticated(doc, op) || publicReason(op) != "" {
				return
			}
			findings = append(findings, Finding{
				Location:  locate(op.Origin),
				Operation: method + " " + path,
				Why:       "Anyone who can reach the API can call this operation, without proving who they are.",
				Fix:       "Add a security requirement to the operation or to the whole spec.",
			})
		})
		return findings
	},
}

// unauthenticated reports whether an operation can be called without
// credentials: it has no security requirement of its own or inherited, an
// explicit `security: []`, or an empty requirement (`- {}`), which OpenAPI
// defines as "anonymous access allowed".
func unauthenticated(doc *openapi3.T, op *openapi3.Operation) bool {
	reqs := doc.Security
	if op.Security != nil {
		reqs = *op.Security
	}
	if len(reqs) == 0 {
		return true
	}
	for _, req := range reqs {
		if len(req) == 0 {
			return true
		}
	}
	return false
}

// forEachOperation calls fn for every operation under paths, in a stable
// order. Webhooks are skipped: the API calls them, nobody calls the API
// through them.
func forEachOperation(doc *openapi3.T, fn func(method, path string, op *openapi3.Operation)) {
	if doc.Paths == nil {
		return
	}
	paths := doc.Paths.Map()
	keys := make([]string, 0, len(paths))
	for path := range paths {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	for _, path := range keys {
		ops := paths[path].Operations()
		methods := make([]string, 0, len(ops))
		for method := range ops {
			methods = append(methods, method)
		}
		sort.Strings(methods)
		for _, method := range methods {
			fn(strings.ToUpper(method), path, ops[method])
		}
	}
}

// locate turns kin-openapi's origin of an element into a Location.
func locate(origin *openapi3.Origin) Location {
	if origin == nil || origin.Key == nil {
		return Location{}
	}
	return Location{File: origin.Key.File, Line: origin.Key.Line, Column: origin.Key.Column}
}

// locateField points at one field of an element (the url of a server), or at
// the element itself when the field has no recorded location.
func locateField(origin *openapi3.Origin, field string) Location {
	if origin != nil {
		if loc, ok := origin.Fields.Lookup(field); ok {
			return Location{File: loc.File, Line: loc.Line, Column: loc.Column}
		}
	}
	return locate(origin)
}

// onePerPlace collects a rule's findings about schema properties. A schema
// shared by several operations is one problem, fixed where it is written:
// one finding at that place, listing every operation that reaches it, so an
// ignore on one of them covers only that one (see applyIgnores).
type onePerPlace struct {
	findings []Finding
	at       map[Location]int // place -> index in findings
}

func (p *onePerPlace) add(f Finding) {
	if i, ok := p.at[f.Location]; ok {
		g := &p.findings[i]
		// Operations are visited one after another, so a repeat (the same
		// schema under two media types) is always the last one added.
		last := g.Operation
		if n := len(g.also); n > 0 {
			last = g.also[n-1]
		}
		if last != f.Operation {
			g.also = append(g.also, f.Operation)
		}
		return
	}
	if p.at == nil {
		p.at = map[Location]int{}
	}
	p.at[f.Location] = len(p.findings)
	p.findings = append(p.findings, f)
}
