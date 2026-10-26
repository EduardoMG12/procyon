package lint

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/words"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc005 = lintRule{
	Rule: report.Rule{
		ID:       "PRC005",
		Title:    "Response returns a secret",
		Severity: report.High,
		OWASP:    "API3:2023 Broken Object Property Level Authorization",
	},
	check: checkPRC005,
}

// checkPRC005 reports response fields holding a secret. Passwords, secrets
// and private keys are reported in any response. Tokens and API keys are
// reported only in GET responses: issuing one from a POST (a login, a new
// key) is how they work, but reading one back must never be possible.
//
// A schema used by several operations is reported once, at the property,
// for every operation that returns it (see onePerPlace).
func checkPRC005(doc *openapi3.T) []report.Finding {
	var found onePerPlace
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		lists := [][][]string{secretWords}
		if method == http.MethodGet {
			lists = append(lists, credentialWords)
		}
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if !holdsValue(prop.Value) || !matchesAny(name, lists) {
				return // hasPassword (a flag), secretRef (an object): about the secret, not the secret
			}
			loc := propertyLocation(prop)
			found.add(report.Finding{
				Location:  loc,
				Operation: method + " " + path,
				Why: fmt.Sprintf("The response includes %q, which holds a secret. Anyone allowed to read this response gets it, "+
					"and responses end up in logs, caches, browser tools and client apps.", name),
				Fix: "Remove the field from the response schema. Check secrets on the server and return only what the client needs.",
			})
		})
	})
	return found.findings
}

// holdsValue reports whether a schema can hold a secret's value: text, a
// number, a list or a map of them, or an object wrapping one ({value: ...}).
// A flag (hasPassword) only says a secret exists, an enum of several values
// is a choice (a permission: secrets: read | write), and other objects
// (secretRef: {name, key}) point at a secret or group fields checked on
// their own. A schema without a type counts unless it has properties or is
// made only of parts that do not count (anyOf: [an object]), to stay on the
// safe side.
func holdsValue(s *openapi3.Schema) bool {
	if s == nil || len(s.Enum) > 1 {
		return false
	}
	if s.Type == nil || len(s.Type.Slice()) == 0 {
		if len(s.Properties) > 0 {
			return wrapsValue(s)
		}
		// Parts that only modify the others (allOf: [{$ref}, {nullable: true}])
		// say nothing about what the value is.
		var parts openapi3.SchemaRefs
		for _, p := range slices.Concat(s.AllOf, s.AnyOf, s.OneOf) {
			if p != nil && p.Value != nil && !modifierOnly(p.Value) {
				parts = append(parts, p)
			}
		}
		if len(parts) == 0 {
			return true
		}
		return slices.ContainsFunc(parts, func(p *openapi3.SchemaRef) bool { return holdsValue(p.Value) })
	}
	for _, t := range []string{"string", "integer", "number"} {
		if s.Type.Includes(t) {
			return true
		}
	}
	if s.Type.Includes("array") {
		return s.Items != nil && holdsValue(s.Items.Value)
	}
	if s.Type.Includes("object") {
		return wrapsValue(s) ||
			(s.AdditionalProperties.Schema != nil && holdsValue(s.AdditionalProperties.Schema.Value)) // a map of secrets
	}
	return false
}

// valueFields name the field of an object that wraps a single value.
var valueFields = []string{"value", "data", "plaintext", "content"}

// wrapsValue reports whether an object wraps its value in a field such as
// value or data: password: {value: "..."} holds a password.
func wrapsValue(s *openapi3.Schema) bool {
	for name, prop := range s.Properties {
		if slices.Contains(valueFields, strings.ToLower(name)) && prop != nil && holdsValue(prop.Value) {
			return true
		}
	}
	return false
}

// modifierOnly reports whether a schema only modifies another (nullable,
// a description) without saying what the value is.
func modifierOnly(s *openapi3.Schema) bool {
	return (s.Type == nil || len(s.Type.Slice()) == 0) && len(s.Properties) == 0 && s.Items == nil &&
		len(s.AllOf)+len(s.AnyOf)+len(s.OneOf) == 0 && s.AdditionalProperties.Schema == nil && len(s.Enum) == 0
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

func matchesAny(name string, lists [][][]string) bool {
	for _, list := range lists {
		if words.Matches(name, list) {
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
