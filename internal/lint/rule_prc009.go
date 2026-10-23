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
func checkPRC009(doc *openapi3.T) []Finding {
	var findings []Finding
	reported := map[Location]bool{}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.RequestBody == nil || op.RequestBody.Value == nil {
			return
		}
		roots := mediaSchemas(op.RequestBody.Value.Content)
		walkProperties(roots, func(name string, prop *openapi3.SchemaRef) bool {
			if prop.Value.ReadOnly {
				return false // the client cannot send it, nor anything inside it
			}
			if !grantsPrivilege(name) {
				return true
			}
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
			return true
		})
	})
	return findings
}

// privilegedWords name fields that decide what a user may do.
var privilegedWords = []string{
	"role", "admin", "administrator", "superuser", "permission", "privilege",
	"scope", "tenant", "papel", "administrador", "permissao", "privilegio",
}

// privilegeSuffixes may follow a privileged word: roleIds, tenantId,
// permissionNames still assign privileges.
var privilegeSuffixes = []string{"id", "ids", "name", "names", "level", "list"}

// grantsPrivilege reports whether a field name is a privilege: a privileged
// word (or its plural) that is the head of the name, followed by nothing
// or by an identifier suffix. userRole, isAdmin, roleIds and tenantId are;
// adminNotes is not.
func grantsPrivilege(name string) bool {
	words := splitWords(name)
	for i, w := range words {
		privileged := slices.ContainsFunc(privilegedWords, func(p string) bool { return sameWord(w, p) })
		if !privileged {
			continue
		}
		rest := words[i+1:]
		if !slices.ContainsFunc(rest, func(r string) bool { return !slices.Contains(privilegeSuffixes, r) }) {
			return true
		}
	}
	return false
}
