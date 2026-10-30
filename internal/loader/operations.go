package loader

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// Spec is a loaded spec, for callers that need its operations rather than a
// lint report: `procyon test` loads the spec it tests through it, so both
// commands read specs, and refuse bad ones, the same way.
type Spec struct {
	doc     *openapi3.T
	files   *specFiles
	ignores []report.Ignore
}

// Operation is one operation of a spec.
type Operation struct {
	Method   string // "GET"
	Path     string // "/orders/{id}"
	Location report.Location
	// Public is true when the operation is marked x-procyon-public.
	Public bool
	// NeedsAuth is true when the spec requires credentials for it (a
	// security requirement, or a required credential parameter).
	NeedsAuth bool
	// Credential is how a caller's token goes into a request: the first way
	// the spec allows. Nil when the operation needs none, or only ways
	// Procyon cannot send (mutual TLS, several schemes at once).
	Credential *Credential
	// Body is a JSON request body built from the spec's example, or nil when
	// the operation takes none or its JSON body has no example.
	Body []byte
	// NeedsBody is true when the spec marks the request body required.
	NeedsBody bool
	// Fields are the top-level properties of the JSON request body's
	// schema, by name, for building malformed requests.
	Fields []Field
}

// Field is one top-level property of a request body's schema.
type Field struct {
	Name     string
	Required bool
	// Types are the JSON types the schema allows ("string", "integer",
	// "null", ...). Empty when it does not say, or says it through allOf,
	// oneOf, anyOf or not: then any value may be valid.
	Types     []string
	Enum      bool    // the schema lists the allowed values
	MaxLength *uint64 // when "string" is one of the types
}

// Key names the operation as reports do: "GET /notes/{id}".
func (o Operation) Key() string {
	return o.Method + " " + o.Path
}

// Credential is where a token goes in a request.
type Credential struct {
	In     string // "header", "query" or "cookie"
	Name   string // "Authorization", "X-API-Key", ...
	Prefix string // "Bearer " for bearer tokens, "" for API keys
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

// AsGiven turns a location as kin-openapi records it into one in the file
// as the user gave it (the original Swagger 2.0 file, a path with spaces).
func (s *Spec) AsGiven(loc report.Location) report.Location {
	return s.files.asGiven(loc)
}

// Ignores are the spec's x-procyon-ignore entries.
func (s *Spec) Ignores() []report.Ignore {
	return s.ignores
}

// Operations returns every operation, sorted by path and then method, so
// the order is the same on every run.
func (s *Spec) Operations() []Operation {
	var ops []Operation
	ForEachOperation(s.doc, func(method, path string, op *openapi3.Operation) {
		ops = append(ops, Operation{
			Method:     method,
			Path:       path,
			Location:   s.files.asGiven(Locate(op.Origin)),
			Public:     PublicReason(op) != "",
			NeedsAuth:  !Unauthenticated(s.doc, path, op),
			Credential: credentialOf(s.doc, path, op),
			Body:       exampleBody(op),
			NeedsBody:  op.RequestBody != nil && op.RequestBody.Value != nil && op.RequestBody.Value.Required,
			Fields:     bodyFields(op),
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
	if name := CredentialParameter(doc, path, op); name != "" {
		for _, p := range OperationParameters(doc, path, op) {
			if p.Name == name {
				return &Credential{In: p.In, Name: p.Name}
			}
		}
	}
	for _, req := range EffectiveSecurity(doc, op) {
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

// jsonBody is the application/json media type of an operation's request
// body, or nil when it has none.
func jsonBody(op *openapi3.Operation) *openapi3.MediaType {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	return op.RequestBody.Value.Content.Get("application/json")
}

// exampleBody returns the JSON example of an operation's request body: the
// media type's example, else its first named example (by name), else the
// schema's example.
func exampleBody(op *openapi3.Operation) []byte {
	media := jsonBody(op)
	if media == nil {
		return nil
	}
	example := media.Example
	if example == nil && len(media.Examples) > 0 {
		names := slices.Sorted(maps.Keys(media.Examples))
		if ref := media.Examples[names[0]]; ref != nil && ref.Value != nil {
			example = ref.Value.Value
		}
	}
	if example == nil && media.Schema != nil && media.Schema.Value != nil {
		example = media.Schema.Value.Example
		if example == nil {
			example = fromProperties(media.Schema.Value)
		}
	}
	if example == nil {
		return nil
	}
	body, err := json.Marshal(example)
	if err != nil {
		return nil
	}
	return body
}

// fromProperties builds an object example from its properties' own
// examples (`password: {type: string, example: pass4}`), or nil when a
// required property has none: a body missing it would be refused for the
// wrong reason.
func fromProperties(schema *openapi3.Schema) any {
	example := map[string]any{}
	for name, prop := range schema.Properties {
		if prop != nil && prop.Value != nil && prop.Value.Example != nil && !prop.Value.ReadOnly {
			example[name] = prop.Value.Example
		}
	}
	for _, name := range schema.Required {
		if _, ok := example[name]; !ok {
			return nil
		}
	}
	if len(example) == 0 {
		return nil
	}
	return example
}

// bodyFields lists the top-level properties of an operation's JSON request
// body, sorted by name.
func bodyFields(op *openapi3.Operation) []Field {
	media := jsonBody(op)
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return nil
	}
	schema := media.Schema.Value
	var fields []Field
	for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
		prop := schema.Properties[name]
		if prop == nil || prop.Value == nil || prop.Value.ReadOnly {
			continue // the client does not send read-only fields
		}
		p := prop.Value
		f := Field{Name: name, Required: slices.Contains(schema.Required, name), Enum: len(p.Enum) > 0}
		composed := len(p.AllOf) > 0 || len(p.OneOf) > 0 || len(p.AnyOf) > 0 || p.Not != nil
		if p.Type != nil && !composed {
			f.Types = slices.Clone(*p.Type)
			if p.Nullable { // OpenAPI 3.0's way of adding "null"
				f.Types = append(f.Types, "null")
			}
		}
		if slices.Contains(f.Types, "string") {
			f.MaxLength = p.MaxLength
		}
		fields = append(fields, f)
	}
	return fields
}
