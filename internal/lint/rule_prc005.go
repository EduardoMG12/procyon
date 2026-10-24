package lint

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc005 = Rule{
	ID:       "PRC005",
	Title:    "Response returns a secret",
	Severity: High,
	OWASP:    "API3:2023 Broken Object Property Level Authorization",
	check:    checkPRC005,
}

// checkPRC005 reports response fields holding a secret. Passwords, secrets
// and private keys are reported in any response. Tokens and API keys are
// reported only in GET responses: issuing one from a POST (a login, a new
// key) is how they work, but reading one back must never be possible.
//
// A schema used by several operations is reported for each of them; the
// engine shows it once (see Run).
func checkPRC005(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		lists := [][][]string{secretWords}
		if method == http.MethodGet {
			lists = append(lists, credentialWords)
		}
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if booleanOnly(prop.Value) || !matchesAny(name, lists) {
				return // hasPassword, passwordSet: about the secret, not the secret
			}
			loc := propertyLocation(prop)
			findings = append(findings, Finding{
				Location:  loc,
				Operation: method + " " + path,
				Why: fmt.Sprintf("The response includes %q, which holds a secret. Anyone allowed to read this response gets it, "+
					"and responses end up in logs, caches, browser tools and client apps.", name),
				Fix: "Remove the field from the response schema. Check secrets on the server and return only what the client needs.",
			})
		})
	})
	return findings
}

// booleanOnly reports whether a schema can only be a boolean (or null):
// type: boolean, or OpenAPI 3.1's type: [boolean, "null"].
func booleanOnly(s *openapi3.Schema) bool {
	if s.Type == nil || !s.Type.Includes("boolean") {
		return false
	}
	for _, t := range s.Type.Slice() {
		if t != "boolean" && t != "null" {
			return false
		}
	}
	return true
}

// propertyLocation points where a property is written. For a $ref property
// that is the property itself, not the shared schema it refers to: two
// properties referring to one schema are two findings, each in its place.
func propertyLocation(prop *openapi3.SchemaRef) Location {
	if prop.Ref != "" {
		if loc := locate(prop.Origin); loc.Line > 0 {
			return loc
		}
	}
	return locate(prop.Value.Origin)
}

func matchesAny(name string, lists [][][]string) bool {
	for _, list := range lists {
		if matches(name, list) {
			return true
		}
	}
	return false
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
