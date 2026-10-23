package lint

import (
	"fmt"
	"slices"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc009 = Rule{
	ID:       "PRC009",
	Title:    "Client can write a privileged field",
	Severity: Medium,
	OWASP:    "API3:2023 Broken Object Property Level Authorization",
	check:    checkPRC009,
}

// checkPRC009 reports request body fields that grant privileges (role,
// isAdmin, permissions, tenantId) and that the client is allowed to send:
// not readOnly, and not inside a readOnly object. Classic mass assignment:
// the server copies the request into the record and the user promotes
// themselves.
//
// Array items are not entered: a list of child records (chat messages with
// a role) is not the record being assigned. OAuth2 token requests (a body
// with grant_type) are skipped: asking for a scope is what they are for.
func checkPRC009(doc *openapi3.T) []Finding {
	var findings []Finding
	reported := map[Location]bool{}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.RequestBody == nil || op.RequestBody.Value == nil {
			return
		}
		roots := mediaSchemas(op.RequestBody.Value.Content)
		if tokenRequest(roots) {
			return
		}
		walkProperties(roots, func(name string, prop *openapi3.SchemaRef) bool {
			if readOnly(prop.Value) {
				return false // the client cannot send it, nor anything inside it
			}
			if grantsPrivilege(name) {
				loc := propertyLocation(prop)
				if !reported[loc] {
					reported[loc] = true
					findings = append(findings, Finding{
						Location:  loc,
						Operation: method + " " + path,
						Why: fmt.Sprintf("The request body accepts %q. If the server copies the request into the record, "+
							"any user can send it and grant themselves privileges.", name),
						Fix: "Mark the field readOnly: true (or remove it from the request schema), and set it on the server " +
							"only through an operation that checks who is allowed to change it.",
					})
				}
			}
			return !prop.Value.Type.Is("array")
		})
	})
	return findings
}

// readOnly reports whether the client cannot send a schema: readOnly on the
// schema itself, or on one of its allOf parts, which is how OpenAPI 3.0
// adds readOnly to a $ref.
func readOnly(s *openapi3.Schema) bool {
	if s.ReadOnly {
		return true
	}
	for _, part := range s.AllOf {
		if part != nil && part.Value != nil && part.Value.ReadOnly {
			return true
		}
	}
	return false
}

// tokenRequest reports whether a request body is an OAuth2 token request.
func tokenRequest(roots []*openapi3.SchemaRef) bool {
	for _, root := range roots {
		if root != nil && root.Value != nil && root.Value.Properties["grant_type"] != nil {
			return true
		}
	}
	return false
}

// privilegedWords name fields that decide what a user may do. Words are
// compared after splitWords, which lowercases and drops accents.
var privilegedWords = [][]string{
	{"role"}, {"admin"}, {"administrator"}, {"superuser"}, {"super", "user"},
	{"permission"}, {"privilege"}, {"scope"}, {"tenant"},
	{"papel"}, {"papeis"}, {"administrador"}, {"administradores"},
	{"permissao"}, {"permissoes"}, {"privilegio"},
}

// privilegeSuffixes may follow a privileged word: roleIds, tenantUuid,
// permissionNames still assign privileges.
var privilegeSuffixes = []string{
	"id", "ids", "uuid", "uuids", "name", "names", "code", "codes",
	"key", "keys", "slug", "type", "level", "list",
}

// grantsPrivilege reports whether a field name is a privilege: a privileged
// word (or its plural) that is the head of the name, followed by nothing
// or by an identifier suffix. userRole, isAdmin, roleIDs and tenantUuid
// are; adminNotes is not.
func grantsPrivilege(name string) bool {
	words := splitWords(name)
	for i := range words {
		for _, entry := range privilegedWords {
			end := i + len(entry)
			if end > len(words) || !slices.EqualFunc(words[i:end], entry, sameWord) {
				continue
			}
			if !slices.ContainsFunc(words[end:], func(w string) bool { return !slices.Contains(privilegeSuffixes, w) }) {
				return true
			}
		}
	}
	return false
}
