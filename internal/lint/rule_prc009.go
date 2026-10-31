package lint

import (
	"fmt"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"

	"github.com/EduardoMG12/procyon/internal/words"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc009 = lintRule{
	Rule: report.Rule{
		ID:       "PRC009",
		Title:    "Client can write a privileged field",
		Severity: report.Medium,
		OWASP:    "API3:2023 Broken Object Property Level Authorization",
	},
	check: checkPRC009,
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
// A role or permission is not reported where assigning it is the
// operation's purpose (PUT /memberships/{username}, see grantPath), nor when
// its enum holds only low values (guestRole: viewer | commenter).
func checkPRC009(doc *openapi3.T) []report.Finding {
	var found onePerPlace
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
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
			if word := privilegeWord(name); word != "" && !assignedOnPurpose(word, path, prop.Value) {
				found.add(report.Finding{
					Location:  propertyLocation(prop),
					Operation: method + " " + path,
					Why: fmt.Sprintf("The request body accepts %q. If the server copies the request into the record, "+
						"any user can send it and grant themselves privileges.", name),
					Fix: "Mark the field readOnly: true (or remove it from the request schema), and set it on the server " +
						"only through an operation that checks who is allowed to change it.",
				})
			}
			return !prop.Value.Type.Is("array")
		})
	})
	return found.findings
}

// roleWords are the privileged words that name a role or a permission:
// the kind of privilege an operation can exist to assign, or an enum can
// list harmlessly. Never admin, superuser or tenant: those are the
// privilege themselves.
var roleWords = []string{"role", "permission", "scope", "papel", "papeis", "permissao", "permissoes"}

// assignedOnPurpose reports whether a privileged field (its privileged
// word, from privilegeWord) is safe to accept: a role or permission on an
// operation that exists to assign it, or one whose enum holds only low
// values.
func assignedOnPurpose(word, path string, s *openapi3.Schema) bool {
	if !slices.Contains(roleWords, word) {
		return false
	}
	return (word != "scope" && grantPath(path)) || lowEnum(s)
}

// grantPathWords name a grant in a path.
var grantPathWords = []string{
	"member", "membership", "collaborator", "invitation", "role", "permission",
	"membro", "papel", "papeis", "permissao", "permissoes",
}

// grantPath reports whether path addresses one grant: a segment naming it,
// followed by a parameter (/orgs/{org}/memberships/{username},
// /collaborators/{user}). A collection (/members) or another resource after
// it (/permissions-check) is not one.
func grantPath(path string) bool {
	segments := strings.Split(path, "/")
	for i := 0; i+1 < len(segments); i++ {
		if !strings.HasPrefix(segments[i+1], "{") {
			continue
		}
		parts := words.Split(segments[i])
		if len(parts) == 1 && words.OneOf(parts[0], grantPathWords) {
			return true
		}
	}
	return false
}

// lowValues are enum values that grant nothing above an ordinary user.
var lowValues = []string{
	"viewer", "view", "reader", "read", "readonly", "guest", "commenter", "comment",
	"member", "user", "basic", "none", "no", "access", "public", "anonymous", "visitor",
	"leitor", "leitura", "convidado", "membro", "usuario", "visitante",
}

// lowEnum reports whether a field (or the items of a list field) is an enum
// of strings made only of low values: guestRole: viewer | commenter. A
// boolean, number or null value, or any other word, makes it a privilege a
// client could pick.
func lowEnum(s *openapi3.Schema) bool {
	if s != nil && s.Type.Includes("array") && s.Items != nil {
		s = s.Items.Value
	}
	if s == nil || len(s.Enum) == 0 {
		return false
	}
	for _, v := range s.Enum {
		text, ok := v.(string)
		if !ok || text == "" {
			return false
		}
		for _, w := range words.Split(text) {
			if !words.OneOf(w, lowValues) {
				return false
			}
		}
	}
	return true
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

// tokenRequest reports whether a request body is an OAuth2 token request:
// it has a grant type field, however it is spelt (grant_type, GrantType).
func tokenRequest(roots []*openapi3.SchemaRef) bool {
	for _, root := range roots {
		if root == nil || root.Value == nil {
			continue
		}
		for name := range root.Value.Properties {
			if slices.Equal(words.Split(name), []string{"grant", "type"}) {
				return true
			}
		}
	}
	return false
}

// privilegedWords name fields that decide what a user may do. Words are
// compared after words.Split, which lowercases and drops accents.
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

// privilegeReferenceWords, right before a privileged word, make it a
// network setting instead: IpPermissions are firewall rules, an IpamScopeId
// names a pool of IP addresses.
var privilegeReferenceWords = []string{"ip", "ipam"}

// privilegeWord returns the privileged word a field name is about, or "":
// a privileged word (or its plural) that is the head of the name, followed
// by nothing or by an identifier suffix, and not right after a reference
// word. userRole, isAdmin, roleIDs and tenantUuid are privileges;
// adminNotes and IpPermissions are not.
func privilegeWord(name string) string {
	parts := words.Split(name)
	for i := range parts {
		for _, entry := range privilegedWords {
			end := i + len(entry)
			if end > len(parts) || !slices.EqualFunc(parts[i:end], entry, words.Same) {
				continue
			}
			if i > 0 && slices.Contains(privilegeReferenceWords, parts[i-1]) {
				continue
			}
			if !slices.ContainsFunc(parts[end:], func(w string) bool { return !slices.Contains(privilegeSuffixes, w) }) {
				return strings.Join(entry, " ")
			}
		}
	}
	return ""
}
