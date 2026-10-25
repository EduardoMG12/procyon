package lint

import (
	"encoding/json"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Changed returns the operations of s ("GET /notes/{id}") that are new
// since base or whose definition changed: their own fields, their path's
// parameters, the security that applies to them and its schemes, or any
// schema, parameter
// or other component they reference, however deep. `procyon test
// --base-spec` tests only those.
func (s *Spec) Changed(base *Spec) map[string]bool {
	before := map[string]string{}
	forEachOperation(base.doc, func(method, path string, op *openapi3.Operation) {
		before[method+" "+path] = fingerprint(base.doc, path, op)
	})
	changed := map[string]bool{}
	forEachOperation(s.doc, func(method, path string, op *openapi3.Operation) {
		key := method + " " + path
		if old, ok := before[key]; !ok || old != fingerprint(s.doc, path, op) {
			changed[key] = true
		}
	})
	return changed
}

// fingerprint is everything that defines an operation, as canonical JSON,
// with every local $ref replaced by what it points to, so a change in a
// shared schema changes every operation that uses it. References to other
// files are kept as written: a change inside one is not seen.
func fingerprint(doc *openapi3.T, path string, op *openapi3.Operation) string {
	security := doc.Security
	if op.Security != nil {
		security = *op.Security
	}
	var pathParams openapi3.Parameters
	if item := doc.Paths.Value(path); item != nil {
		pathParams = item.Parameters
	}
	// Requirements name their schemes instead of referencing them.
	schemes := map[string]any{}
	for _, req := range security {
		for name := range req {
			if doc.Components != nil {
				schemes[name] = doc.Components.SecuritySchemes[name]
			}
		}
	}
	components := generic(doc.Components)
	whole := generic(map[string]any{"operation": op, "pathParameters": pathParams, "security": security, "schemes": schemes})
	data, _ := json.Marshal(inline(whole, components, map[string]bool{})) // maps marshal with sorted keys
	return string(data)
}

// generic turns a value into plain JSON maps and slices.
func generic(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(data, &out) // what json.Marshal wrote always decodes
	return out
}

// inline replaces {"$ref": "#/components/..."} with the component, at any
// depth. A reference already being inlined (a recursive schema) stays a
// reference, so the walk ends.
func inline(v any, components any, inlining map[string]bool) any {
	switch v := v.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok && strings.HasPrefix(ref, "#/components/") && !inlining[ref] {
			if target := pointerIn(components, strings.TrimPrefix(ref, "#/components/")); target != nil {
				inlining[ref] = true
				out := inline(target, components, inlining)
				delete(inlining, ref)
				return out
			}
		}
		out := map[string]any{}
		for k, field := range v {
			out[k] = inline(field, components, inlining)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = inline(item, components, inlining)
		}
		return out
	}
	return v
}

// pointerIn follows "schemas/Note" through nested maps, unescaping JSON
// pointer segments.
func pointerIn(v any, path string) any {
	for _, part := range strings.Split(path, "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[strings.NewReplacer("~1", "/", "~0", "~").Replace(part)]
	}
	return v
}
