package loader

// Guards around kin-openapi's Swagger 2.0 converter: inputs it would hang,
// blow up or crash on are refused with a clear error, and what it silently
// drops is either restored or refused.

import (
	"cmp"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml/ast"
)

// operationServers gives each operation with its own schemes the servers
// they mean, which the converter drops. Without a host there is no URL to
// build, as for the spec's own schemes.
func operationServers(doc2 *openapi2.T, doc3 *openapi3.T) {
	if doc2.Host == "" {
		return
	}
	basePath := cmp.Or(doc2.BasePath, "/")
	for path, item := range doc2.Paths {
		for method, op := range item.Operations() {
			if len(op.Schemes) == 0 {
				continue
			}
			op3 := doc3.Paths.Value(path).GetOperation(method)
			if op3 == nil {
				continue
			}
			servers := openapi3.Servers{}
			for _, scheme := range op.Schemes {
				u := url.URL{Scheme: scheme, Host: doc2.Host, Path: basePath}
				servers = append(servers, &openapi3.Server{URL: u.String()})
			}
			op3.Servers = &servers
		}
	}
}

// swaggerNames rewrites the OpenAPI 3 names in a converter message to the
// Swagger 2.0 ones the user wrote.
var swaggerNames = strings.NewReplacer(
	"#/components/schemas/", "#/definitions/",
	"#/components/parameters/", "#/parameters/",
	"#/components/responses/", "#/responses/",
	"#/components/requestBodies/", "#/parameters/",
	"#/components/securitySchemes/", "#/securityDefinitions/",
)

// pathItemRef returns the pointer of the first path item that is a $ref,
// which the converter silently drops, or "".
func pathItemRef(raw any) string {
	top, _ := raw.(map[string]any)
	paths, _ := top["paths"].(map[string]any)
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		if !strings.HasPrefix(path, "/") {
			continue // an x- extension, not a path item
		}
		if item, ok := paths[path].(map[string]any); ok {
			if _, isRef := item["$ref"]; isRef {
				return "/paths/" + escapePointer(path) + "/$ref"
			}
		}
	}
	return ""
}

// maxMediaTypes bounds the media types kept per consumes or produces list.
// The converter copies a body or response schema once per media type, and
// every copy has the same schema, so the rest add nothing but work.
const maxMediaTypes = 8

// limitMediaTypes trims every consumes and produces list in a decoded
// Swagger 2.0 document to maxMediaTypes entries.
func limitMediaTypes(node any) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if list, ok := v.([]any); ok && (k == "consumes" || k == "produces") && len(list) > maxMediaTypes {
				n[k] = list[:maxMediaTypes]
				continue
			}
			limitMediaTypes(v)
		}
	case []any:
		for _, v := range n {
			limitMediaTypes(v)
		}
	}
}

// maxAliasNodes bounds how much YAML aliases may expand to, in nodes plus
// the bytes of their text (one long string costs its length, not 1).
const maxAliasNodes = 1 << 20

// limitAliases returns an error when the YAML aliases in a parsed file
// would expand to more than maxAliasNodes.
//
// Each anchor's expanded size is computed once and reused by its aliases
// (memoization), so counting never expands anything itself.
func limitAliases(file *ast.File) error {
	sizes := map[string]int{} // anchor name -> nodes it expands to
	total := 0                // nodes added by aliases
	var size func(node ast.Node) int
	size = func(node ast.Node) int {
		switch n := node.(type) {
		case nil:
			return 0
		case *ast.DocumentNode:
			return size(n.Body)
		case *ast.MappingNode:
			sum := 1
			for _, v := range n.Values {
				sum += size(v)
			}
			return sum
		case *ast.MappingValueNode:
			return size(n.Key) + size(n.Value)
		case *ast.SequenceNode:
			sum := 1
			for _, v := range n.Values {
				sum += size(v)
			}
			return sum
		case *ast.TagNode:
			return size(n.Value)
		case *ast.AnchorNode:
			s := min(size(n.Value), maxAliasNodes+1)
			sizes[n.Name.GetToken().Value] = s
			return s
		case *ast.AliasNode:
			s := sizes[n.Value.GetToken().Value]
			total = min(total+s, maxAliasNodes+1) // no overflow
			return min(s, maxAliasNodes+1)
		}
		if t := node.GetToken(); t != nil {
			return 1 + len(t.Value)
		}
		return 1
	}
	for _, doc := range file.Docs {
		size(doc)
	}
	if total > maxAliasNodes {
		return fmt.Errorf("YAML aliases expand to more than %d nodes and bytes; write the repeated parts out once", maxAliasNodes)
	}
	return nil
}

// nullPlaces are the pointers whose value must be an object in Swagger 2.0
// and on which kin-openapi's converter would crash if it were null.
var nullPlaces = regexp.MustCompile(`^/paths/[^/]+(/[^/]+)?$|/parameters/[^/]+$|/responses/[^/]+$|/headers/[^/]+$|^/definitions/[^/]+$|^/securityDefinitions/[^/]+$`)

// nullEntry returns the pointer of the first null where Swagger 2.0 needs an
// object, in a stable order, or "".
func nullEntry(node any, pointer string) string {
	switch n := node.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(n)) {
			child := pointer + "/" + escapePointer(k)
			if n[k] == nil && nullPlaces.MatchString(child) {
				return child
			}
			if freeForm(pointer, k) {
				continue // a value where null is valid
			}
			if found := nullEntry(n[k], child); found != "" {
				return found
			}
		}
	case []any:
		for i, v := range n {
			child := pointer + "/" + strconv.Itoa(i)
			if v == nil && nullPlaces.MatchString(child) {
				return child
			}
			if found := nullEntry(v, child); found != "" {
				return found
			}
		}
	}
	return ""
}

// freeForm reports whether key k of the object at pointer holds a free-form
// value (an example, a default, an enum, an extension). The same words can
// also name an entry ("default" response, a definition called "example"),
// which is not free-form.
func freeForm(pointer, k string) bool {
	for _, named := range []string{"/paths", "/responses", "/parameters", "/definitions", "/securityDefinitions", "/headers", "/properties"} {
		if strings.HasSuffix(pointer, named) {
			return false
		}
	}
	return k == "example" || k == "examples" || k == "default" || k == "enum" || strings.HasPrefix(k, "x-")
}

// externalRef returns the first $ref in a decoded document that points to
// another file, or "".
func externalRef(node any) string {
	switch n := node.(type) {
	case map[string]any:
		if ref, ok := n["$ref"].(string); ok && !strings.HasPrefix(ref, "#") {
			return ref
		}
		for _, k := range slices.Sorted(maps.Keys(n)) { // the same $ref on every run
			if ref := externalRef(n[k]); ref != "" {
				return ref
			}
		}
	case []any:
		for _, v := range n {
			if ref := externalRef(v); ref != "" {
				return ref
			}
		}
	}
	return ""
}
