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

var prc007 = lintRule{
	Rule: report.Rule{
		ID:       "PRC007",
		Title:    "Object addressed by ID without authentication",
		Severity: report.High,
		OWASP:    "API1:2023 Broken Object Level Authorization",
	},
	check: checkPRC007,
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
func checkPRC007(doc *openapi3.T) []report.Finding {
	var findings []report.Finding
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		// Marking an operation public (x-procyon-public) does not change
		// that anyone can call it: it only says it is meant to be so.
		if !loader.Unauthenticated(doc, path, op) {
			return
		}
		param := objectIdentifier(doc, path, op)
		if param == "" {
			return
		}
		findings = append(findings, report.Finding{
			Location:  loader.Locate(op.Origin),
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
	for _, p := range loader.OperationParameters(doc, path, op) {
		if p.In == openapi3.ParameterInPath && identifies(p.Name) {
			return p.Name
		}
	}
	return ""
}

// identifies reports whether a path parameter's name identifies an object:
// its last word is an identifier word, or it is one lowercase word ending
// in "id" ({userid}, {orderid}), which words.Split cannot split.
func identifies(name string) bool {
	parts := words.Split(name)
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if slices.Contains(identifierWords, last) {
		return true
	}
	return len(parts) == 1 && len(last) > 3 && (strings.HasSuffix(last, "id") || strings.HasSuffix(last, "ids"))
}
