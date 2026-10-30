package loader

import (
	"maps"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/EduardoMG12/procyon/internal/words"
	"github.com/getkin/kin-openapi/openapi3"
)

// credentialParameterWords name a parameter that carries the caller's
// credential, when a spec sends it as a parameter rather than through a
// security scheme.
var credentialParameterWords = [][]string{
	{"authorization"}, {"access", "token"}, {"auth", "token"},
	{"session", "token"}, {"apikey"}, {"api", "key"}, {"access", "key"},
}

// Unauthenticated reports whether an operation can be called without
// credentials: it has no security requirement of its own or inherited, an
// explicit `security: []`, or an empty requirement (`- {}`), which OpenAPI
// defines as "anonymous access allowed" — and no credential parameter.
func Unauthenticated(doc *openapi3.T, path string, op *openapi3.Operation) bool {
	if CredentialParameter(doc, path, op) != "" {
		return false
	}
	reqs := EffectiveSecurity(doc, op)
	if len(reqs) == 0 {
		return true
	}
	for _, req := range reqs {
		if len(req) == 0 {
			return true
		}
	}
	return false
}

// EffectiveSecurity is the security that applies to an operation: its own
// requirements when it has any (even an explicit `security: []`), else the
// spec's default.
func EffectiveSecurity(doc *openapi3.T, op *openapi3.Operation) openapi3.SecurityRequirements {
	if op.Security != nil {
		return *op.Security
	}
	return doc.Security
}

// CredentialParameter returns the name of the parameter through which an
// operation requires a credential instead of a security scheme, as older
// specs often do, or "": a required header or query parameter named like a
// credential (credentialParameterWords: Authorization, x-access-token,
// api_key). A bare token is not one: it is as often a one-time link's, a
// captcha's or a device's.
func CredentialParameter(doc *openapi3.T, path string, op *openapi3.Operation) string {
	for _, p := range OperationParameters(doc, path, op) {
		if !p.Required || (p.In != openapi3.ParameterInHeader && p.In != openapi3.ParameterInQuery) {
			continue
		}
		if words.Matches(p.Name, credentialParameterWords) {
			return p.Name
		}
	}
	return ""
}

// OperationParameters returns the parameters that apply to an operation:
// its own, and its path's that it does not redefine (same name and in).
func OperationParameters(doc *openapi3.T, path string, op *openapi3.Operation) []*openapi3.Parameter {
	var params []*openapi3.Parameter
	own := map[[2]string]bool{}
	for _, p := range op.Parameters {
		if p != nil && p.Value != nil {
			params = append(params, p.Value)
			own[[2]string{p.Value.Name, p.Value.In}] = true
		}
	}
	if item := doc.Paths.Value(path); item != nil {
		for _, p := range item.Parameters {
			if p != nil && p.Value != nil && !own[[2]string{p.Value.Name, p.Value.In}] {
				params = append(params, p.Value)
			}
		}
	}
	return params
}

// ForEachOperation calls fn for every operation under paths, in a stable
// order. Webhooks are skipped: the API calls them, nobody calls the API
// through them.
func ForEachOperation(doc *openapi3.T, fn func(method, path string, op *openapi3.Operation)) {
	if doc.Paths == nil {
		return
	}
	paths := doc.Paths.Map()
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		ops := paths[path].Operations()
		for _, method := range slices.Sorted(maps.Keys(ops)) {
			fn(strings.ToUpper(method), path, ops[method])
		}
	}
}

// Locate turns kin-openapi's origin of an element into a Location.
func Locate(origin *openapi3.Origin) report.Location {
	if origin == nil || origin.Key == nil {
		return report.Location{}
	}
	return report.Location{File: origin.Key.File, Line: origin.Key.Line, Column: origin.Key.Column}
}

// LocateField points at one field of an element (the url of a server), or at
// the element itself when the field has no recorded location.
func LocateField(origin *openapi3.Origin, field string) report.Location {
	if origin != nil {
		if loc, ok := origin.Fields.Lookup(field); ok {
			return report.Location{File: loc.File, Line: loc.Line, Column: loc.Column}
		}
	}
	return Locate(origin)
}

// ForEachScheme calls fn once for every defined security scheme, by name. An
// alias ($ref to another scheme) is skipped: it is the same scheme, and its
// finding belongs where the scheme is written.
func ForEachScheme(doc *openapi3.T, fn func(name string, scheme *openapi3.SecurityScheme)) {
	if doc.Components == nil {
		return
	}
	schemes := doc.Components.SecuritySchemes
	for _, name := range slices.Sorted(maps.Keys(schemes)) {
		if ref := schemes[name]; ref != nil && ref.Ref == "" && ref.Value != nil {
			fn(name, ref.Value)
		}
	}
}
