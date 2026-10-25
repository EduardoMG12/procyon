package lint

import (
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Spec is a loaded spec, for callers that need its operations rather than a
// lint report: `procyon test` loads the spec it tests through it, so both
// commands read specs, and refuse bad ones, the same way.
type Spec struct {
	doc     *openapi3.T
	files   *specFiles
	ignores []*ignore
}

// Operation is one operation of a spec.
type Operation struct {
	Method   string // "GET"
	Path     string // "/orders/{id}"
	Location Location
	// Public is true when the operation is marked x-procyon-public.
	Public bool
	// Credential is how a caller's token goes into a request: the first way
	// the spec allows. Nil when the operation needs none, or only ways
	// Procyon cannot send (mutual TLS, several schemes at once).
	Credential *Credential
}

// Credential is where a token goes in a request.
type Credential struct {
	In     string // "header", "query" or "cookie"
	Name   string // "Authorization", "X-API-Key", ...
	Prefix string // "Bearer " for bearer tokens, "" for API keys
}

// Load reads and validates the spec at path, like Run, without linting it.
func Load(path string, opts Options) (*Spec, error) {
	doc, files, err := load(path, opts)
	if err != nil {
		return nil, err
	}
	// A typo in an ignore stops `procyon test` too.
	ignores, err := parseIgnores(doc, files.asGiven, files.back != nil)
	if err != nil {
		return nil, err
	}
	return &Spec{doc: doc, files: files, ignores: ignores}, nil
}

// Operations returns every operation, sorted by path and then method, so
// the order is the same on every run.
func (s *Spec) Operations() []Operation {
	var ops []Operation
	forEachOperation(s.doc, func(method, path string, op *openapi3.Operation) {
		ops = append(ops, Operation{
			Method:     method,
			Path:       path,
			Location:   s.files.asGiven(locate(op.Origin)),
			Public:     publicReason(op) != "",
			Credential: credentialOf(s.doc, path, op),
		})
	})
	return ops
}

// Sources returns the lines of every spec file read, for Report.Sources.
func (s *Spec) Sources() map[string][]string {
	return s.files.lines
}

// credentialOf returns how a token is sent to an operation: a credential
// parameter (see credentialParameter) wins, then the first security
// requirement made of one scheme Procyon can fill.
func credentialOf(doc *openapi3.T, path string, op *openapi3.Operation) *Credential {
	if name := credentialParameter(doc, path, op); name != "" {
		for _, p := range operationParameters(doc, path, op) {
			if p.Name == name {
				return &Credential{In: p.In, Name: p.Name}
			}
		}
	}
	reqs := doc.Security
	if op.Security != nil {
		reqs = *op.Security
	}
	for _, req := range reqs {
		if len(req) != 1 || doc.Components == nil {
			continue
		}
		for name := range req { // the only one
			ref := doc.Components.SecuritySchemes[name]
			if ref == nil || ref.Value == nil {
				continue
			}
			if c := schemeCredential(ref.Value); c != nil {
				return c
			}
		}
	}
	return nil
}

func schemeCredential(scheme *openapi3.SecurityScheme) *Credential {
	switch {
	case scheme.Type == "http" && strings.EqualFold(scheme.Scheme, "bearer"),
		scheme.Type == "oauth2", scheme.Type == "openIdConnect":
		return &Credential{In: "header", Name: "Authorization", Prefix: "Bearer "}
	case scheme.Type == "http" && strings.EqualFold(scheme.Scheme, "basic"):
		return &Credential{In: "header", Name: "Authorization", Prefix: "Basic "}
	case scheme.Type == "apiKey" && scheme.In != "" && scheme.Name != "":
		return &Credential{In: scheme.In, Name: scheme.Name}
	}
	return nil
}
