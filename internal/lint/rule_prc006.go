package lint

import (
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc006 = Rule{
	ID:       "PRC006",
	Title:    "Personal data returned without authentication",
	Severity: High,
	OWASP:    "API3:2023 Broken Object Property Level Authorization",
	check:    checkPRC006,
}

// piiWords name personal data. Words are compared after splitWords, which
// lowercases and drops accents.
var piiWords = [][]string{
	{"email"}, {"e", "mail"}, {"phone"}, {"telefone"}, {"celular"},
	{"cpf"}, {"rg"}, {"ssn"}, {"social", "security", "number"},
	{"passport"}, {"passaporte"}, {"national", "id"}, {"tax", "id"},
	{"address"}, {"endereco"},
	{"birth", "date"}, {"birthdate"}, {"birthday"}, {"date", "of", "birth"}, {"dob"},
	{"data", "nascimento"}, {"nascimento"},
	{"first", "name"}, {"last", "name"}, {"full", "name"}, {"surname"},
	{"nome", "completo"}, {"sobrenome"},
}

// checkPRC006 reports personal data in the responses of operations anyone
// can call: no security requirement, whether or not the operation is
// marked public. Marking it public says it is meant to be open, which makes
// exposing personal data through it worse, not acceptable.
func checkPRC006(doc *openapi3.T) []Finding {
	var findings []Finding
	reported := map[Location]bool{}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !reachableAnonymously(doc, op) {
			return
		}
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if booleanOnly(prop.Value) || !matches(name, piiWords) {
				return // emailVerified: about the data, not the data
			}
			loc := propertyLocation(prop)
			if reported[loc] {
				return
			}
			reported[loc] = true
			findings = append(findings, Finding{
				Location:  loc,
				Operation: method + " " + path,
				Why: fmt.Sprintf("This operation needs no authentication and returns %q, personal data. "+
					"Anyone can collect it, for every record they can reach, which breaks privacy laws such as the GDPR and LGPD.", name),
				Fix: "Require authentication for the operation, or remove the field from what it returns to anonymous callers.",
			})
		})
	})
	return findings
}

// reachableAnonymously reports whether anyone can call op without
// credentials. Marking an operation public (x-procyon-public) does not
// change that: it only says it is meant to be so.
func reachableAnonymously(doc *openapi3.T, op *openapi3.Operation) bool {
	return unauthenticated(doc, op)
}
