package lint

import (
	"fmt"
	"net/http"
	"slices"

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
	{"email"}, {"e", "mail"}, {"phone"}, {"telephone"}, {"cellphone"},
	{"mobile", "number"}, {"telefone"}, {"celular"},
	{"cpf"}, {"rg"}, {"ssn"}, {"social", "security", "number"},
	{"passport"}, {"passaporte"}, {"national", "id"}, {"national", "identifier"}, {"tax", "id"},
	{"address"}, {"endereco"},
	{"birth", "date"}, {"birthdate"}, {"birthday"}, {"date", "of", "birth"}, {"dob"},
	{"data", "nascimento"}, {"nascimento"},
	{"first", "name"}, {"last", "name"}, {"full", "name"}, {"surname"},
	{"nome", "completo"}, {"sobrenome"},
}

// piiDescribingWords, right after a personal-data word, mean the field is
// about the data, not the data: emailTemplate, emailSettings,
// emailVerifiedAt, addressFormat. On top of the general describingWords.
var piiDescribingWords = append(slices.Clone(describingWords),
	"template", "templates", "settings", "config", "configuration", "verified",
	"verification", "enabled", "notifications", "preferences", "provider",
	"server", "host", "port", "domain",
)

// piiReferenceWords, right before a personal-data word, make it something
// other than a person's data: supportEmail (the company's), walletAddress,
// listenAddress, ipAddress.
var piiReferenceWords = append(slices.Clone(referenceWords),
	"support", "sender", "noreply", "reply", "from", "wallet", "contract",
	"listen", "ip", "mac", "server", "host", "bind", "remote", "local", "web",
)

// checkPRC006 reports personal data in what a GET returns to anyone: no
// security requirement, whether or not the operation is marked public.
// Marking it public says it is meant to be open, which makes exposing
// personal data through it worse, not acceptable. Other methods are not
// checked: a login or sign-up returns the caller's own data.
func checkPRC006(doc *openapi3.T) []Finding {
	var found onePerPlace
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if method != http.MethodGet || !reachableAnonymously(doc, path, op) {
			return
		}
		forEachResponseProperty(op, func(name string, prop *openapi3.SchemaRef) {
			if !textual(prop.Value) || !matchesWith(name, piiWords, piiDescribingWords, piiReferenceWords) {
				return // emailVerified, emailSettings: about the data, not the data
			}
			loc := propertyLocation(prop)
			found.add(Finding{
				Location:  loc,
				Operation: method + " " + path,
				Why: fmt.Sprintf("This operation needs no authentication and returns %q, personal data. "+
					"Anyone can collect it, for every record they can reach, which breaks privacy laws such as the GDPR and LGPD.", name),
				Fix: "Require authentication for the operation, or remove the field from what it returns to anonymous callers.",
			})
		})
	})
	return found.findings
}

// textual reports whether a schema holds text, or a list of texts: personal
// data is a value such as an address, never a flag or an object of
// settings. A schema without a type counts, to stay on the safe side.
func textual(s *openapi3.Schema) bool {
	if s.Type == nil || len(s.Type.Slice()) == 0 {
		return len(s.Properties) == 0
	}
	if s.Type.Includes("string") {
		return true
	}
	return s.Type.Includes("array") && s.Items != nil && s.Items.Value != nil && s.Items.Value.Type.Includes("string")
}

// reachableAnonymously reports whether anyone can call op without
// credentials. Marking an operation public (x-procyon-public) does not
// change that: it only says it is meant to be so.
func reachableAnonymously(doc *openapi3.T, path string, op *openapi3.Operation) bool {
	return unauthenticated(doc, path, op)
}
