package lint

import (
	"sort"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// What the rules about schema properties (PRC005, PRC006, PRC008, PRC009)
// share: the schemas an operation receives and returns, a walk over their
// properties, and where a property is written.

// requestSchemas returns the schemas of an operation's request body, one per
// media type, or nil when it has no body.
func requestSchemas(op *openapi3.Operation) []*openapi3.SchemaRef {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	return mediaSchemas(op.RequestBody.Value.Content)
}

// forEachResponseProperty calls fn for every property of every schema an
// operation's responses can return.
func forEachResponseProperty(op *openapi3.Operation, fn func(name string, prop *openapi3.SchemaRef)) {
	if op.Responses == nil {
		return
	}
	var roots []*openapi3.SchemaRef
	for _, response := range op.Responses.Map() {
		if response != nil && response.Value != nil {
			roots = append(roots, mediaSchemas(response.Value.Content)...)
		}
	}
	walkProperties(roots, func(name string, prop *openapi3.SchemaRef) bool {
		fn(name, prop)
		return true
	})
}

// mediaSchemas returns the schema of each media type of a body (some may be
// nil).
func mediaSchemas(content openapi3.Content) []*openapi3.SchemaRef {
	var schemas []*openapi3.SchemaRef
	for _, media := range content {
		if media != nil {
			schemas = append(schemas, media.Schema)
		}
	}
	return schemas
}

// walkProperties calls fn for every property of the schemas under roots,
// following nested objects, array items, allOf/oneOf/anyOf and
// additionalProperties. fn returns whether to look inside the property.
// Each schema is visited once, so recursive schemas (a User with a manager
// User) terminate.
func walkProperties(roots []*openapi3.SchemaRef, fn func(name string, prop *openapi3.SchemaRef) bool) {
	visited := map[*openapi3.Schema]bool{}
	var walk func(ref *openapi3.SchemaRef)
	walk = func(ref *openapi3.SchemaRef) {
		if ref == nil || ref.Value == nil || visited[ref.Value] {
			return
		}
		s := ref.Value
		visited[s] = true
		names := make([]string, 0, len(s.Properties))
		for name := range s.Properties {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if prop := s.Properties[name]; prop != nil && prop.Value != nil && fn(name, prop) {
				walk(prop)
			}
		}
		walk(s.Items)
		for _, group := range []openapi3.SchemaRefs{s.AllOf, s.OneOf, s.AnyOf} {
			for _, sub := range group {
				walk(sub)
			}
		}
		walk(s.AdditionalProperties.Schema)
	}
	for _, root := range roots {
		walk(root)
	}
}

// propertyLocation points where a property is written. For a $ref property
// that is the property itself, not the shared schema it refers to: two
// properties referring to one schema are two findings, each in its place.
func propertyLocation(prop *openapi3.SchemaRef) report.Location {
	if prop.Ref != "" {
		if loc := loader.Locate(prop.Origin); loc.Line > 0 {
			return loc
		}
	}
	return loader.Locate(prop.Value.Origin)
}

// readOnly reports whether the client cannot send a schema: readOnly on the
// schema itself, or on one of its allOf parts, which is how OpenAPI 3.0
// adds readOnly to a $ref.
func readOnly(s *openapi3.Schema) bool {
	if s.ReadOnly {
		return true
	}
	for _, part := range s.AllOf {
		if part != nil && part.Value != nil && part.Value.ReadOnly {
			return true
		}
	}
	return false
}

// untyped reports whether a schema has no type keyword, or an empty one:
// {}, or a schema made only of properties or allOf/anyOf/oneOf parts.
func untyped(s *openapi3.Schema) bool {
	return s.Type == nil || len(s.Type.Slice()) == 0
}
