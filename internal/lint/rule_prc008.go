package lint

import (
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc008 = Rule{
	ID:       "PRC008",
	Title:    "Unbounded input or output",
	Severity: Low,
	OWASP:    "API4:2023 Unrestricted Resource Consumption",
	check:    checkPRC008,
}

// boundedFormats have a length fixed by their format, so a missing
// maxLength is not a gap. byte (base64) is not one: it can be any size.
var boundedFormats = []string{"date", "date-time", "time", "uuid", "ipv4", "ipv6"}

// pagingParameters are query parameter names that limit how much a list
// returns, compared lowercased and without a leading "$" (OData's $top).
var pagingParameters = []string{
	"limit", "page", "per_page", "perpage", "page_size", "pagesize", "size",
	"cursor", "offset", "first", "after", "starting_after", "take", "top",
	"skip", "page_token", "pagetoken",
}

// checkPRC008 reports where the spec lets a client send or receive an
// unbounded amount of data: request strings without maxLength (a whole
// body, a property, or the items of a list), request arrays without
// maxItems, and GET operations returning a whole list with no way to ask
// for a page.
func checkPRC008(doc *openapi3.T) []Finding {
	var findings []Finding
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		add := func(loc Location, why, fix string) {
			findings = append(findings, Finding{Location: loc, Operation: method + " " + path, Why: why, Fix: fix})
		}
		if method == http.MethodGet && returnsList(op) && !paged(doc, path, op) {
			add(locate(op.Origin),
				"This operation returns a whole list with no way to ask for one page, so one request can make the server read and send every record.",
				"Add paging query parameters (limit and cursor, or page and per_page) and a maximum page size.")
		}
		if op.RequestBody == nil || op.RequestBody.Value == nil {
			return
		}
		check := func(s *openapi3.Schema, loc Location) {
			if why, fix := unbounded(s); why != "" {
				add(loc, why, fix)
			}
		}
		roots := mediaSchemas(op.RequestBody.Value.Content)
		for _, root := range roots {
			if root != nil && root.Value != nil {
				check(root.Value, locate(root.Value.Origin)) // the body itself is a list or a text
			}
		}
		walkProperties(roots, func(name string, prop *openapi3.SchemaRef) bool {
			if readOnly(prop.Value) {
				return false
			}
			check(prop.Value, propertyLocation(prop))
			return true
		})
	})
	return findings
}

// unbounded explains what is unbounded about a request schema, or returns
// empty strings when it is bounded.
func unbounded(s *openapi3.Schema) (why, fix string) {
	switch {
	case unboundedString(s):
		return "Nothing limits how long this text can be, so a client can send megabytes in one field and make the server parse, store or process all of it.",
			"Add maxLength with the longest value the field really needs."
	case s.Type.Includes("array") && s.MaxItems == nil:
		return "Nothing limits how many items this list can hold, so one request can carry millions of them.",
			"Add maxItems with the largest number the operation really needs."
	case s.Type.Includes("array") && s.Items != nil && s.Items.Value != nil && unboundedString(s.Items.Value):
		return "Nothing limits how long each text in this list can be, so even a short list can carry megabytes.",
			"Add maxLength to the list's items."
	}
	return "", ""
}

func unboundedString(s *openapi3.Schema) bool {
	return s.Type.Includes("string") && s.MaxLength == nil && len(s.Enum) == 0 &&
		!slices.Contains(boundedFormats, s.Format)
}

// returnsList reports whether a successful response's body is an array.
func returnsList(op *openapi3.Operation) bool {
	if op.Responses == nil {
		return false
	}
	for code, response := range op.Responses.Map() {
		if !strings.HasPrefix(code, "2") || response == nil || response.Value == nil {
			continue
		}
		for _, schema := range mediaSchemas(response.Value.Content) {
			if schema != nil && schema.Value != nil && schema.Value.Type.Includes("array") {
				return true
			}
		}
	}
	return false
}

// paged reports whether the operation, or its path, has a query parameter
// that limits a page.
func paged(doc *openapi3.T, path string, op *openapi3.Operation) bool {
	params := slices.Clone(op.Parameters)
	if item := doc.Paths.Value(path); item != nil {
		params = append(params, item.Parameters...)
	}
	for _, p := range params {
		if p == nil || p.Value == nil || p.Value.In != openapi3.ParameterInQuery {
			continue
		}
		name := strings.TrimPrefix(strings.ToLower(p.Value.Name), "$")
		if slices.Contains(pagingParameters, name) {
			return true
		}
	}
	return false
}
