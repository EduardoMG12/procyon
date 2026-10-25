package lint

import "github.com/getkin/kin-openapi/openapi3"

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
			Method:   method,
			Path:     path,
			Location: s.files.asGiven(locate(op.Origin)),
			Public:   publicReason(op) != "",
		})
	})
	return ops
}

// Sources returns the lines of every spec file read, for Report.Sources.
func (s *Spec) Sources() map[string][]string {
	return s.files.lines
}
