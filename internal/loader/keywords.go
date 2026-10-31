package loader

import (
	"maps"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// dropUnknownKeywords removes, from every schema of an OpenAPI 3.1 or later
// document, the keywords kin-openapi does not know. kin-openapi keeps them
// with the extensions, and validation refuses an extension not named x-.
// But a 3.1 schema is a JSON Schema 2020-12 one, which allows any keyword
// (OpenAI's optional, Vercel's regex) and ignores those it does not know,
// as Procyon does (so --base-spec does not see a change to one either). In
// a 3.0 schema the keywords are a fixed list: unknown ones stay errors. A
// schema the walk misses keeps its keywords and is refused, as before.
func dropUnknownKeywords(doc *openapi3.T) {
	w := schemaWalk{schemas: map[*openapi3.Schema]bool{}, items: map[*openapi3.PathItem]bool{}}
	for _, item := range doc.Paths.Map() {
		w.pathItem(item)
	}
	for _, item := range doc.Webhooks {
		w.pathItem(item)
	}
	if c := doc.Components; c != nil {
		for _, s := range c.Schemas {
			w.schema(s)
		}
		for _, p := range c.Parameters {
			w.parameter(p)
		}
		w.headers(c.Headers)
		for _, body := range c.RequestBodies {
			w.requestBody(body)
		}
		for _, r := range c.Responses {
			w.response(r)
		}
		w.callbacks(c.Callbacks)
	}
}

// schemaWalk visits every schema of a document once, and every path item
// once: shared and recursive schemas are common, and a callback can lead
// back to a path item already walked.
type schemaWalk struct {
	schemas map[*openapi3.Schema]bool
	items   map[*openapi3.PathItem]bool
}

func (w schemaWalk) schema(ref *openapi3.SchemaRef) {
	if ref == nil || ref.Value == nil || w.schemas[ref.Value] {
		return
	}
	s := ref.Value
	w.schemas[s] = true
	maps.DeleteFunc(s.Extensions, func(key string, _ any) bool { return !strings.HasPrefix(key, "x-") })
	for _, list := range []openapi3.SchemaRefs{s.OneOf, s.AnyOf, s.AllOf, s.PrefixItems} {
		for _, sub := range list {
			w.schema(sub)
		}
	}
	for _, sub := range []*openapi3.SchemaRef{s.Not, s.Items, s.Contains, s.PropertyNames, s.If, s.Then, s.Else, s.ContentSchema,
		s.AdditionalProperties.Schema, s.UnevaluatedItems.Schema, s.UnevaluatedProperties.Schema} {
		w.schema(sub)
	}
	for _, named := range []openapi3.Schemas{s.Properties, s.PatternProperties, s.DependentSchemas, s.Defs} {
		for _, sub := range named {
			w.schema(sub)
		}
	}
}

func (w schemaWalk) pathItem(item *openapi3.PathItem) {
	if item == nil || w.items[item] {
		return
	}
	w.items[item] = true
	for _, p := range item.Parameters {
		w.parameter(p)
	}
	for _, op := range item.Operations() {
		for _, p := range op.Parameters {
			w.parameter(p)
		}
		w.requestBody(op.RequestBody)
		for _, r := range op.Responses.Map() {
			w.response(r)
		}
		w.callbacks(op.Callbacks)
	}
}

func (w schemaWalk) callbacks(callbacks openapi3.Callbacks) {
	for _, cb := range callbacks {
		if cb != nil && cb.Value != nil {
			for _, item := range cb.Value.Map() {
				w.pathItem(item)
			}
		}
	}
}

func (w schemaWalk) parameter(p *openapi3.ParameterRef) {
	if p != nil && p.Value != nil {
		w.schema(p.Value.Schema)
		w.content(p.Value.Content)
	}
}

func (w schemaWalk) headers(headers openapi3.Headers) {
	for _, h := range headers {
		if h != nil && h.Value != nil {
			w.schema(h.Value.Schema)
			w.content(h.Value.Content)
		}
	}
}

func (w schemaWalk) requestBody(body *openapi3.RequestBodyRef) {
	if body != nil && body.Value != nil {
		w.content(body.Value.Content)
	}
}

func (w schemaWalk) response(r *openapi3.ResponseRef) {
	if r != nil && r.Value != nil {
		w.headers(r.Value.Headers)
		w.content(r.Value.Content)
	}
}

func (w schemaWalk) content(content openapi3.Content) {
	for _, media := range content {
		if media == nil {
			continue
		}
		w.schema(media.Schema)
		w.schema(media.ItemSchema)
		for _, enc := range media.Encoding {
			if enc != nil {
				w.headers(enc.Headers)
			}
		}
	}
}
