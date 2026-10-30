package loader

import (
	"fmt"
	"testing"
)

// A Swagger 2.0 request body is a "body" parameter. Its converted
// requestBody points at that parameter's list entry: at the entry's $ref
// when it refers to #/parameters, else at its name. Locations are counted
// by hand in the fixture.
func TestSwaggerRequestBodyLocation(t *testing.T) {
	tests := []struct{ spec, method, path, want string }{
		{"swagger-2.0-edges.yaml", "POST", "/admins", "65:11"}, // - $ref: "#/parameters/Body"
		{"swagger-2.0-edges.yaml", "PUT", "/accounts", "46:9"}, // declared on the path item
		{"swagger-2.0-body.json", "POST", "/users", "12:13"},
	}
	for _, tt := range tests {
		spec, err := Load("../../testdata/specs/"+tt.spec, anyRule)
		if err != nil {
			t.Fatal(err)
		}
		body := spec.Doc().Paths.Find(tt.path).GetOperation(tt.method).RequestBody
		origin := body.Origin // where the $ref is written
		if body.Ref == "" {
			origin = body.Value.Origin
		}
		loc := spec.AsGiven(Locate(origin))
		if got := fmt.Sprintf("%d:%d", loc.Line, loc.Column); got != tt.want {
			t.Errorf("%s %s %s: request body at %s, want %s", tt.spec, tt.method, tt.path, got, tt.want)
		}
	}
}
