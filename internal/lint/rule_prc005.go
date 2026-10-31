package lint

import (
	"fmt"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/EduardoMG12/procyon/internal/words"

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

// checkPRC005 reports response fields holding a secret. Passwords and
// private keys are reported in any response. Secrets are reported in any
// response but that of a POST creating or rotating them: a new webhook's
// signing secret is shown once, when it is made. Tokens and API keys are
// reported only in GET responses: issuing one from a POST (a login, a new
// key) is how they work, but reading one back must never be possible.
//
// A schema used by several operations is reported once, at the property,
// for every operation that returns it (see onePerPlace).
func checkPRC005(doc *openapi3.T) []report.Finding {
	var found onePerPlace
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if !holdsSecret(method, path, name, prop.Value) {
				return
			}
			found.add(report.Finding{
				Location:  propertyLocation(prop),
				Operation: loader.OperationKey(method, path),
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

// The words of a secret's name, by how a response may hold it.
var (
	// secretWords name values that must never appear in a response.
	secretWords = [][]string{
		{"password"}, {"passwd"}, {"passphrase"}, {"senha"},
		{"private", "key"}, {"chave", "privada"},
	}

	// issuedSecretWords name values a server generates and shows once, in
	// the response that creates or rotates them (a webhook's signing
	// secret, an OAuth app's client secret), and never again.
	issuedSecretWords = [][]string{{"secret"}, {"segredo"}}

	// credentialWords name values an API legitimately hands out once (a
	// login returns a token, creating a key returns the key) but that must
	// never be readable again afterwards.
	credentialWords = [][]string{
		{"token"}, {"apikey"}, {"api", "key"}, {"access", "key"},
	}

	// credentialReferenceWords, right before a credential word, make it
	// something other than a credential, on top of the general
	// words.Reference: an identifier (uniqueToken, idempotencyToken), or a
	// token made for the client to hold (EC2's ClientToken, an idempotency
	// key the client chose; a payment widget's client_token). They do not
	// apply to secretWords: clientSecret is a secret.
	credentialReferenceWords = append(slices.Clone(words.Reference), "unique", "idempotency", "client")
)

// holdsSecret reports whether a response field of the operation method
// path holds a secret: a secret word and a value of secretTypes (an issued
// secret word too, unless the POST creates or rotates it), or, in a GET, a
// credential word and a value of credentialTypes. hasPassword (a flag) and
// secretRef (an object) are about a secret, not the secret.
func holdsSecret(method, path, name string, s *openapi3.Schema) bool {
	secret := words.Matches(name, secretWords) ||
		words.Matches(name, issuedSecretWords) && (method != "POST" || !createsOrRotates(path))
	if secret && holdsValue(s, secretTypes, map[*openapi3.Schema]bool{}) {
		return true
	}
	return method == "GET" && words.Match(name, credentialWords, words.Describing, credentialReferenceWords) &&
		holdsValue(s, credentialTypes, map[*openapi3.Schema]bool{})
}

// createsOrRotates reports whether a POST to path makes something new: its
// last segment is not a parameter, so it goes to a collection (POST
// /webhooks) or to an action (POST /webhooks/{id}/rotate-secret), not to
// one record (POST /webhooks/{id}, an update).
func createsOrRotates(path string) bool {
	last := path[strings.LastIndex(path, "/")+1:]
	return !strings.HasPrefix(last, "{")
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
	if untyped(s) {
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
	return untyped(s) && len(s.Properties) == 0 && s.Items == nil &&
		len(s.AllOf)+len(s.AnyOf)+len(s.OneOf) == 0 && s.AdditionalProperties.Schema == nil && len(s.Enum) == 0
}
