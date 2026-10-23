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
// maxLength is not a gap.
var boundedFormats = []string{"date", "date-time", "time", "uuid", "ipv4", "ipv6", "byte", "int32", "int64"}

// pagingParameters are query parameter names that limit how much a list
// returns.
var pagingParameters = []string{
	"limit", "page", "per_page", "perpage", "page_size", "pagesize", "size",
	"cursor", "offset", "first", "after", "take", "top", "max", "count",
}

// checkPRC008 reports where the spec lets a client send or receive an
// unbounded amount of data: request strings without maxLength, request
// arrays without maxItems, and GET operations returning a whole list with
// no way to ask for a page.
func checkPRC008(doc *openapi3.T) []Finding {
	var findings []Finding
	reported := map[Location]bool{}
	add := func(f Finding) {
		if !reported[f.Location] {
			reported[f.Location] = true
			findings = append(findings, f)
		}
	}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		operation := method + " " + path
		if method == http.MethodGet && returnsList(op) && !paged(doc, path, op) {
			add(Finding{
				Location:  locate(op.Origin),
				Operation: operation,
				Why:       "This operation returns a whole list with no way to ask for one page, so one request can make the server read and send every record.",
				Fix:       "Add paging query parameters (limit and cursor, or page and per_page) and a maximum page size.",
			})
		}
		if op.RequestBody == nil || op.RequestBody.Value == nil {
			return
		}
		walkProperties(mediaSchemas(op.RequestBody.Value.Content), func(name string, prop *openapi3.SchemaRef) bool {
			s := prop.Value
			if readOnly(s) {
				return false
			}
			switch {
			case s.Type.Is("string") && s.MaxLength == nil && len(s.Enum) == 0 && !slices.Contains(boundedFormats, s.Format):
				add(Finding{
					Location:  propertyLocation(prop),
					Operation: operation,
					Why:       "Nothing limits how long this text can be, so a client can send megabytes in one field and make the server parse, store or process all of it.",
					Fix:       "Add maxLength with the longest value the field really needs.",
				})
			case s.Type.Is("array") && s.MaxItems == nil:
				add(Finding{
					Location:  propertyLocation(prop),
					Operation: operation,
					Why:       "Nothing limits how many items this list can hold, so one request can carry millions of them.",
					Fix:       "Add maxItems with the largest number the operation really needs.",
				})
			}
			return true
		})
	})
	return findings
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
			if schema != nil && schema.Value != nil && schema.Value.Type.Is("array") {
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
		if slices.Contains(pagingParameters, strings.ToLower(p.Value.Name)) {
			return true
		}
	}
	return false
}
