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
func fromSwagger(data []byte) (converted []byte, back func(position) (position, bool), err error) {
	original, err := keyPositions(data)
	if err != nil {
		return nil, nil, err
	}
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
	// Decoding to JSON expands YAML aliases, and a few hundred bytes of
	// nested aliases expand to gigabytes: refuse before expanding.
	if err := limitAliases(data); err != nil {
		return nil, nil, err
	}
	asJSON, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, nil, err
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
	if err != nil {
		return nil, nil, fmt.Errorf("converting Swagger 2.0 to OpenAPI 3: %s", swaggerNames(err.Error()))
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

// swaggerSections maps a section of an OpenAPI 3 document's components to
// the Swagger 2.0 section that holds the same elements.
var swaggerSections = map[string]string{"schemas": "definitions", "securitySchemes": "securityDefinitions",
	"parameters": "parameters", "responses": "responses", "requestBodies": "parameters"}

// swaggerPointer translates a JSON pointer in the converted OpenAPI 3
// document to the pointer of the same element in the Swagger 2.0 one.
func swaggerPointer(pointer string, doc2 *openapi2.T) string {
	parts := strings.Split(pointer, "/")[1:]
	switch {
	case len(parts) >= 2 && parts[0] == "components":
		renamed := swaggerSections[parts[1]]
		if renamed == "" {
			return ""
		}
		rest := parts[2:]
		switch {
		case parts[1] == "securitySchemes" && len(rest) > 1 && rest[1] == "flows":
			rest = rest[:1] // a 2.0 scheme holds its single flow itself
		case (parts[1] == "responses" || parts[1] == "requestBodies") && len(rest) >= 4 && rest[1] == "content":
			// <name>/content/<type>/schema/... -> <name>/schema/...
			rest = append(rest[:1:1], rest[3:]...)
		}
		return "/" + strings.Join(append([]string{renamed}, rest...), "/")
	case len(parts) >= 1 && parts[0] == "servers":
		return "/schemes" // 2.0 builds the server URL from schemes, host and basePath
	case len(parts) >= 4 && parts[0] == "paths":
		op := parts[:3] // paths, path, method
		rest := parts[3:]
		// responses/200/content/<type>/schema/... -> responses/200/schema/...
		if len(rest) >= 5 && rest[0] == "responses" && rest[2] == "content" {
			rest = append(rest[:2:2], rest[4:]...)
		}
		if rest[0] == "servers" {
			return "/" + strings.Join(append(op, "schemes"), "/") // see operationServers
		}
		// requestBody/content/<type>/schema/properties/<field>/... ->
		// parameters/<formData field>/name
		if rest[0] == "requestBody" && len(rest) >= 6 && rest[4] == "properties" {
			if owner, i, key := formParameter(doc2, unescapePointer(op[1]), op[2], unescapePointer(rest[5])); i >= 0 {
				if owner == "path" {
					op = op[:2]
				}
				return "/" + strings.Join(append(op, "parameters", strconv.Itoa(i), key), "/")
			}
		}
		// requestBody/content/<type>/schema/... -> parameters/<body>/schema/...
		// requestBody, its $ref or its content -> parameters/<body>/name, or
		// parameters/<body>/$ref when the entry refers to #/parameters
		if rest[0] == "requestBody" {
			owner, i, key := bodyParameter(doc2, unescapePointer(op[1]), op[2])
			if i < 0 {
				return "/" + strings.Join(append(op, "parameters"), "/")
			}
			if owner == "path" {
				op = op[:2] // declared on the path item, shared by its operations
			}
			tail := []string{key}
			if len(rest) >= 4 {
				tail = rest[3:]
			}
			rest = append([]string{"parameters", strconv.Itoa(i)}, tail...)
		}
		return "/" + strings.Join(append(op, rest...), "/")
	}
	return pointer
}

// bodyParameter finds the body parameter of an operation in the Swagger 2.0
// document, as swaggerParameter does.
func bodyParameter(doc2 *openapi2.T, path, method string) (owner string, index int, key string) {
	return swaggerParameter(doc2, path, method, func(p *openapi2.Parameter) bool {
		return p.In == "body"
	})
}

// formParameter finds the formData parameter called name of an operation,
// as swaggerParameter does.
func formParameter(doc2 *openapi2.T, path, method, name string) (owner string, index int, key string) {
	return swaggerParameter(doc2, path, method, func(p *openapi2.Parameter) bool {
		return p.In == "formData" && p.Name == name
	})
}

// swaggerParameter finds the first parameter of an operation in the Swagger
// 2.0 document that match accepts: on the operation ("operation"), else on
// its path item ("path"). A list entry that refers to #/parameters is
// matched as the parameter it refers to. It returns where, the index there
// and the key to point at in the entry: "$ref" when it refers to
// #/parameters, else "name"; or -1.
func swaggerParameter(doc2 *openapi2.T, path, method string, match func(*openapi2.Parameter) bool) (owner string, index int, key string) {
	item := doc2.Paths[path]
	if item == nil {
		return "", -1, ""
	}
	find := func(params openapi2.Parameters) (int, string) {
		for i, p := range params {
			key := "name"
			if p != nil && p.Ref != "" {
				p = doc2.Parameters[strings.TrimPrefix(p.Ref, "#/parameters/")]
				key = "$ref"
			}
			if p != nil && match(p) {
				return i, key
			}
		}
		return -1, ""
	}
	if op := item.GetOperation(strings.ToUpper(method)); op != nil {
		if i, key := find(op.Parameters); i >= 0 {
			return "operation", i, key
		}
	}
	if i, key := find(item.Parameters); i >= 0 {
		return "path", i, key
	}
	return "", -1, ""
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
	out := map[position]string{}
	err := walkKeys(data, func(pointer string, p position) { out[p] = pointer })
	return out, err
}

// keyPositions maps the JSON pointer of every mapping key in a YAML or JSON
// text to its position.
func keyPositions(data []byte) (map[string]position, error) {
	out := map[string]position{}
	err := walkKeys(data, func(pointer string, p position) { out[pointer] = p })
	return out, err
}

func walkKeys(data []byte, visit func(pointer string, p position)) error {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return err
	}
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
	return nil
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
