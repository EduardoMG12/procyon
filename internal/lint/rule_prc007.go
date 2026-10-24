package lint

import (
	"fmt"
	"slices"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc007 = Rule{
	ID:       "PRC007",
	Title:    "Object addressed by ID without authentication",
	Severity: High,
	OWASP:    "API1:2023 Broken Object Level Authorization",
	check:    checkPRC007,
}

// identifierWords, as the last word of a path parameter's name, mean it
// identifies one object: {id}, {userId}, {order_id}, {slug}, {username}.
var identifierWords = []string{
	"id", "ids", "uuid", "guid", "key", "slug", "number", "num", "no",
	"code", "name", "username", "login", "handle", "title", "email",
}

// checkPRC007 reports operations anyone can call that address an object by
// an identifier in the path. Without authentication there is no "whose
// object is this" check possible, so anyone can walk the identifiers and
// read every object: the classic broken object level authorization.
func checkPRC007(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if !reachableAnonymously(doc, op) {
			return
		}
		param := objectIdentifier(doc, path, op)
		if param == "" {
			return
		}
		findings = append(findings, Finding{
			Location:  locate(op.Origin),
			Operation: method + " " + path,
			Why: fmt.Sprintf("This operation needs no authentication and picks an object by {%s}. "+
				"Nobody can check whose object it is, so anyone can try identifiers one after another and reach every object.", param),
			Fix: "Require authentication and check on the server that the caller may access the object. " +
				"If the objects really are public, use identifiers that cannot be guessed and say so with x-procyon-public.",
		})
	})
	return findings
}

// objectIdentifier returns the first path parameter of op (or its path)
// that identifies an object, or "".
func objectIdentifier(doc *openapi3.T, path string, op *openapi3.Operation) string {
	params := slices.Clone(op.Parameters)
	if item := doc.Paths.Value(path); item != nil {
		params = append(params, item.Parameters...)
	}
	for _, p := range params {
		if p == nil || p.Value == nil || p.Value.In != openapi3.ParameterInPath {
			continue
		}
		words := splitWords(p.Value.Name)
		if len(words) > 0 && slices.Contains(identifierWords, words[len(words)-1]) {
			return p.Value.Name
		}
	}
	return ""
}
