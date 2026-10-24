package lint

import (
	"fmt"
	"slices"
	"strings"

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
// Generic words such as code, number or name are left out: {langCode} and
// {pageNumber} pick a language and a page, not an object.
var identifierWords = []string{
	"id", "ids", "uuid", "guid", "uid", "identifier", "key", "slug", "sku",
	"username", "login", "handle", "title", "email",
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
				"If the objects really are public, use identifiers that cannot be guessed and ignore this finding " +
				"with x-procyon-ignore and the reason.",
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
		if identifies(p.Value.Name) {
			return p.Value.Name
		}
	}
	return ""
}

// identifies reports whether a path parameter's name identifies an object:
// its last word is an identifier word, or it is one lowercase word ending
// in "id" ({userid}, {orderid}), which splitWords cannot split.
func identifies(name string) bool {
	words := splitWords(name)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	if slices.Contains(identifierWords, last) {
		return true
	}
	return len(words) == 1 && len(last) > 3 && (strings.HasSuffix(last, "id") || strings.HasSuffix(last, "ids"))
}
