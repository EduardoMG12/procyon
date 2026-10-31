package lint

import (
	"fmt"
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
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if !holdsSecret(method, name, prop.Value) {
				return
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

// The types a secret's value can have. A password can be a number (a PIN
// typed integer), but a token or an API key is always text: a number named
// after tokens counts them (total_tokens, num_tokens_per_chunk).
var (
	secretTypes     = []string{"string", "integer", "number"}
	credentialTypes = []string{"string"}
)

// holdsSecret reports whether a response field of an operation with this
// method holds a secret: a secret word and a value of secretTypes, or, in
// a GET, a credential word and a value of credentialTypes. hasPassword (a
// flag) and secretRef (an object) are about a secret, not the secret.
func holdsSecret(method, name string, s *openapi3.Schema) bool {
	if words.Matches(name, secretWords) && holdsValue(s, secretTypes, map[*openapi3.Schema]bool{}) {
		return true
	}
	return method == "GET" && words.Match(name, credentialWords, words.Describing, credentialReferenceWords) &&
		holdsValue(s, credentialTypes, map[*openapi3.Schema]bool{})
}

// holdsValue reports whether a schema can hold a secret's value: one of
// types, a list or a map of them, or an object wrapping one ({value: ...}).
// A flag (hasPassword) only says a secret exists, an enum of several values
// is a choice (a permission: secrets: read | write), and other objects
// (secretRef: {name, key}) point at a secret or group fields checked on
// their own. A schema without a type counts unless it has properties or is
// made only of parts that do not count (anyOf: [an object]), to stay on the
// safe side.
//
// seen holds the schemas already looked at, the visited set walkProperties
// also keeps: a recursive schema (a map of maps) meets itself again, and
// would otherwise be checked forever. A schema already seen adds nothing:
// it is either still being checked further up, or was checked and holds no
// value (a value found anywhere returns true at once).
func holdsValue(s *openapi3.Schema, types []string, seen map[*openapi3.Schema]bool) bool {
	if s == nil || seen[s] || len(s.Enum) > 1 {
		return false
	}
	seen[s] = true
	if s.Type == nil || len(s.Type.Slice()) == 0 {
		if len(s.Properties) > 0 {
			return wrapsValue(s, types, seen)
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
		return slices.ContainsFunc(parts, func(p *openapi3.SchemaRef) bool { return holdsValue(p.Value, types, seen) })
	}
	for _, t := range types {
		if s.Type.Includes(t) {
			return true
		}
	}
	if s.Type.Includes("array") {
		return s.Items != nil && holdsValue(s.Items.Value, types, seen)
	}
	if s.Type.Includes("object") {
		return wrapsValue(s, types, seen) ||
			(s.AdditionalProperties.Schema != nil && holdsValue(s.AdditionalProperties.Schema.Value, types, seen)) // a map of secrets
	}
	return false
}

// valueFields name the field of an object that wraps a single value.
var valueFields = []string{"value", "data", "plaintext", "content"}

// wrapsValue reports whether an object wraps its value in a field such as
// value or data: password: {value: "..."} holds a password.
func wrapsValue(s *openapi3.Schema, types []string, seen map[*openapi3.Schema]bool) bool {
	for name, prop := range s.Properties {
		if slices.Contains(valueFields, strings.ToLower(name)) && prop != nil && holdsValue(prop.Value, types, seen) {
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
