package lint

import (
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// lintRule is one lint rule: what reports show about it, and its check.
type lintRule struct {
	Rule
	// check returns the rule's findings; the engine fills in Finding.Rule.
	check func(doc *openapi3.T) []Finding
}

// Rules returns every lint rule, in ID order.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = r.Rule
	}
	return out
}

// rules is every lint rule, in ID order.
var rules = []lintRule{prc001, prc002, prc003, prc004, prc005, prc006, prc007, prc008, prc009, prc010, prc011}

var prc001 = lintRule{
	Rule: Rule{
		ID:       "PRC001",
		Title:    "Operation has no authentication",
		Severity: High,
		OWASP:    "API2:2023 Broken Authentication",
	},
	check: func(doc *openapi3.T) []Finding {
		var findings []Finding
		forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
			if !unauthenticated(doc, path, op) || publicReason(op) != "" {
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
// defines as "anonymous access allowed" — and no credential parameter.
func unauthenticated(doc *openapi3.T, path string, op *openapi3.Operation) bool {
	if credentialParameter(doc, path, op) != "" {
		return false
	}
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

// credentialParameter returns the name of the parameter through which an
// operation requires a credential instead of a security scheme, as older
// specs often do, or "": a required header or query parameter named like a
// credential (credentialParameterWords: Authorization, x-access-token,
// api_key). A bare token is not one: it is as often a one-time link's, a
// captcha's or a device's.
func credentialParameter(doc *openapi3.T, path string, op *openapi3.Operation) string {
	for _, p := range operationParameters(doc, path, op) {
		if !p.Required || (p.In != openapi3.ParameterInHeader && p.In != openapi3.ParameterInQuery) {
			continue
		}
		if matches(p.Name, credentialParameterWords) {
			return p.Name
		}
	}
	return ""
}

// operationParameters returns the parameters that apply to an operation:
// its own, and its path's that it does not redefine (same name and in).
func operationParameters(doc *openapi3.T, path string, op *openapi3.Operation) []*openapi3.Parameter {
	var params []*openapi3.Parameter
	own := map[[2]string]bool{}
	for _, p := range op.Parameters {
		if p != nil && p.Value != nil {
			params = append(params, p.Value)
			own[[2]string{p.Value.Name, p.Value.In}] = true
		}
	}
	if item := doc.Paths.Value(path); item != nil {
		for _, p := range item.Parameters {
			if p != nil && p.Value != nil && !own[[2]string{p.Value.Name, p.Value.In}] {
				params = append(params, p.Value)
			}
		}
	}
	return params
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
		if n := len(g.Also); n > 0 {
			last = g.Also[n-1]
		}
		if last != f.Operation {
			g.Also = append(g.Also, f.Operation)
		}
		return
	}
	if p.at == nil {
		p.at = map[Location]int{}
	}
	p.at[f.Location] = len(p.findings)
	p.findings = append(p.findings, f)
}
