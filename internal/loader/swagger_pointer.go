package loader

// How fromSwagger's back finds, for an element of the converted OpenAPI 3
// document, the same element in the Swagger 2.0 one: by translating its
// JSON pointer (/components/schemas/User to /definitions/User).

import (
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
)

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
