package loader

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// position is a line and column in a file.
type position struct{ line, column int }

// positionError is an input error about a place in the spec file; at is
// zero when the place is unknown.
type positionError struct {
	at      position
	message string
}

func (e *positionError) Error() string {
	if e.at.line == 0 {
		return e.message
	}
	return fmt.Sprintf("%d:%d: %s", e.at.line, e.at.column, e.message)
}

// fromSwagger converts a Swagger 2.0 spec to an OpenAPI 3 document (as
// JSON text, which Procyon then loads like any spec) and returns how to
// map a location in that converted text back to the original file.
//
// kin-openapi's converter keeps no locations, so each location is mapped
// through JSON pointers: the key at a position in the converted text has a
// pointer (/components/schemas/User), which is translated to the Swagger
// 2.0 pointer for the same element (/definitions/User) and looked up in the
// original file. When the exact element has no counterpart, the nearest
// ancestor that does is used.
//
// file is data's syntax tree, or nil for JSON, which load does not parse as
// YAML. Parsing a large spec takes seconds, so it is parsed only once.
func fromSwagger(data []byte, file *ast.File) (converted []byte, back func(position) (position, bool), err error) {
	isJSON := file == nil
	if isJSON {
		if file, err = parser.ParseBytes(data, 0); err != nil {
			return nil, nil, err
		}
	}
	original := keyPositions(file)
	// at is an error about an element of the original file, at its place.
	at := func(pointer, format string, args ...any) error {
		// paths > /users > $ref: a pointer reads badly once a key has a "/".
		parts := strings.Split(pointer, "/")[1:]
		for i := range parts {
			parts[i] = unescapePointer(parts[i])
		}
		err := &positionError{message: strings.Join(parts, " > ") + ": " + fmt.Sprintf(format, args...)}
		for p := pointer; p != ""; p = parentPointer(p) {
			if pos, ok := original[p]; ok {
				err.at = pos
				break
			}
		}
		return err
	}
	asJSON := data
	if !isJSON {
		// Decoding to JSON expands YAML aliases, and a few hundred bytes of
		// nested aliases expand to gigabytes: refuse before expanding. JSON
		// has no aliases.
		if err := limitAliases(file); err != nil {
			return nil, nil, err
		}
		if asJSON, err = yaml.YAMLToJSON(data); err != nil {
			return nil, nil, err
		}
	}
	var raw any
	if err := json.Unmarshal(asJSON, &raw); err != nil {
		return nil, nil, fmt.Errorf("reading Swagger 2.0: %w", err)
	}
	top, _ := raw.(map[string]any)
	if _, isNumber := top["swagger"].(float64); isNumber {
		top["swagger"] = "2.0" // swagger: 2.0 without quotes is a YAML number
	}
	if pointer := nullEntry(raw, ""); pointer != "" {
		return nil, nil, at(pointer, "empty (null); remove it or give it a value")
	}
	if pointer := pathItemRef(raw); pointer != "" {
		return nil, nil, at(pointer, "a $ref on a path item is not supported in Swagger 2.0 specs "+
			"(write the operations in place, or convert the spec to OpenAPI 3)")
	}
	limitMediaTypes(raw)
	if asJSON, err = json.Marshal(raw); err != nil {
		return nil, nil, err
	}
	// The converter is not hardened against every malformed document; a
	// panic in it must be an input error, never a crash.
	defer func() {
		if r := recover(); r != nil {
			converted, back, err = nil, nil, fmt.Errorf("converting Swagger 2.0 to OpenAPI 3 failed: %v", r)
		}
	}()
	if ref := externalRef(raw); ref != "" {
		return nil, nil, fmt.Errorf("$ref %q: Swagger 2.0 specs must be one file "+
			"(bundle it first, or convert it to OpenAPI 3, where $refs to other files are supported)", ref)
	}
	var doc2 openapi2.T
	if err := json.Unmarshal(asJSON, &doc2); err != nil {
		// A value of the wrong kind (a list where a schema must be) names its
		// place as dotted, pointer-escaped keys: point at it in the file.
		if wrong, ok := errors.AsType[*json.UnmarshalTypeError](err); ok && wrong.Field != "" {
			return nil, nil, at("/"+strings.ReplaceAll(wrong.Field, ".", "/"),
				"is %s, where Swagger 2.0 expects %s", jsonKind(wrong.Value), goKind(wrong.Type))
		}
		return nil, nil, fmt.Errorf("reading Swagger 2.0: %w", err)
	}
	doc3, err := openapi2conv.ToV3(&doc2)
	if pointer := failedPathsRef(raw, err); pointer != "" {
		return nil, nil, at(pointer, "this $ref into #/paths cannot be converted to OpenAPI 3 "+
			"(move what it points at to #/definitions, #/parameters or #/responses, and refer to it there)")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("converting Swagger 2.0 to OpenAPI 3: %s", swaggerNames.Replace(err.Error()))
	}
	operationServers(&doc2, doc3)
	if doc3.Paths == nil {
		doc3.Paths = openapi3.NewPaths() // the converter leaves an empty paths as null
	}
	converted, err = json.MarshalIndent(doc3, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	pointerAt, err := keyPointers(converted)
	if err != nil {
		return nil, nil, err
	}
	back = func(p position) (position, bool) {
		pointer, ok := pointerAt[p]
		if !ok {
			return position{}, false
		}
		for v2 := swaggerPointer(pointer, &doc2); v2 != ""; v2 = parentPointer(v2) {
			if p, ok := original[v2]; ok {
				return p, true
			}
		}
		// Never report a position of the converted text as if it were in
		// the original: point at the start of the file instead.
		return position{1, 1}, true
	}
	return converted, back, nil
}

func parentPointer(pointer string) string {
	i := strings.LastIndex(pointer, "/")
	if i <= 0 {
		return ""
	}
	return pointer[:i]
}

// keyPointers maps the position of every mapping key in a YAML or JSON
// text to its JSON pointer.
func keyPointers(data []byte) (map[position]string, error) {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return nil, err
	}
	out := map[position]string{}
	walkKeys(file, func(pointer string, p position) { out[p] = pointer })
	return out, nil
}

// keyPositions maps the JSON pointer of every mapping key in a parsed YAML
// or JSON text to its position.
func keyPositions(file *ast.File) map[string]position {
	out := map[string]position{}
	walkKeys(file, func(pointer string, p position) { out[pointer] = p })
	return out
}

func walkKeys(file *ast.File, visit func(pointer string, p position)) {
	var walk func(node ast.Node, pointer string)
	walk = func(node ast.Node, pointer string) {
		switch n := node.(type) {
		case *ast.DocumentNode:
			walk(n.Body, pointer)
		case *ast.MappingNode:
			for _, v := range n.Values {
				walk(v, pointer)
			}
		case *ast.MappingValueNode:
			key := keyText(n.Key)
			child := pointer + "/" + escapePointer(key)
			if t := n.Key.GetToken(); t != nil {
				visit(child, position{t.Position.Line, t.Position.Column})
			}
			walk(n.Value, child)
		case *ast.SequenceNode:
			for i, v := range n.Values {
				walk(v, pointer+"/"+strconv.Itoa(i))
			}
		case *ast.TagNode:
			walk(n.Value, pointer)
		case *ast.AnchorNode:
			walk(n.Value, pointer)
		}
	}
	for _, doc := range file.Docs {
		walk(doc, "")
	}
}

func keyText(key ast.MapKeyNode) string {
	if s, ok := key.(*ast.StringNode); ok {
		return s.Value
	}
	if t := key.GetToken(); t != nil {
		return t.Value
	}
	return key.String()
}

// A JSON pointer writes a ~ in a key as ~0 and a / as ~1. A Replacer is
// safe for concurrent use, so one of each serves every call.
var (
	pointerEscaper   = strings.NewReplacer("~", "~0", "/", "~1")
	pointerUnescaper = strings.NewReplacer("~1", "/", "~0", "~")
)

func escapePointer(s string) string {
	return pointerEscaper.Replace(s)
}

func unescapePointer(s string) string {
	return pointerUnescaper.Replace(s)
}

// jsonKind names a JSON value kind as encoding/json reports it ("array").
func jsonKind(kind string) string {
	if name, ok := map[string]string{
		"array": "a list", "object": "an object", "string": "text", "number": "a number", "bool": "true or false",
	}[kind]; ok {
		return name
	}
	return kind
}

// goKind names what a Go type expects, in JSON terms.
func goKind(t reflect.Type) string {
	if t == nil {
		return "another kind of value"
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		return "an object"
	case reflect.Slice, reflect.Array:
		return "a list"
	case reflect.String:
		return "text"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int64, reflect.Uint64, reflect.Float64:
		return "a number"
	}
	return "another kind of value"
}
