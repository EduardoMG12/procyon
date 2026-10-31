package loader

import (
	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// Spec is a loaded spec: its document, its ignores and the files it was
// read from. `procyon lint` and `procyon test` both load specs through it,
// so both read specs, and refuse bad ones, the same way. Its operations, as
// a runtime test calls them, are in operations.go.
type Spec struct {
	doc     *openapi3.T
	files   *specFiles
	ignores []report.Ignore
}

// Load reads and validates the spec at path, and parses its ignores: a
// typo in one stops the run.
func Load(path string, opts Options) (*Spec, error) {
	doc, files, err := load(path, opts)
	if err != nil {
		return nil, err
	}
	ignores, err := parseIgnores(doc, files.asGiven, files.back != nil, opts.KnownRule)
	if err != nil {
		return nil, err
	}
	return &Spec{doc: doc, files: files, ignores: ignores}, nil
}

// Doc is the spec as kin-openapi loaded it, for lint rules.
func (s *Spec) Doc() *openapi3.T {
	return s.doc
}

// ServerPath is the path of the spec's first server ("/b2b/v2" in
// "https://shop.example/b2b/v2", or a Swagger 2.0 basePath), with its
// variables at their defaults: the spec's paths are relative to it. It is
// "" when the spec has no server, the server has no path, or its URL does
// not parse.
func (s *Spec) ServerPath() string {
	if len(s.doc.Servers) == 0 {
		return ""
	}
	path, err := s.doc.Servers[0].BasePath()
	if err != nil || path == "/" {
		return ""
	}
	return path
}

// AsGiven turns a location as kin-openapi records it into one in the file
// as the user gave it (the original Swagger 2.0 file, a path with spaces).
func (s *Spec) AsGiven(loc report.Location) report.Location {
	return s.files.asGiven(loc)
}

// Ignores are the spec's x-procyon-ignore entries.
func (s *Spec) Ignores() []report.Ignore {
	return s.ignores
}

// Sources returns the lines of every spec file read, for Report.Sources.
func (s *Spec) Sources() map[string][]string {
	return s.files.lines
}
