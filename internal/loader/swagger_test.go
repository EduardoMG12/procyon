package loader

import (
	"fmt"
	"strings"
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

// The converter cannot resolve a $ref into a path's response schema: the
// user is pointed at the $ref and told where to move what it points at.
func TestSwaggerRefIntoPathsIsRefusedAtTheRef(t *testing.T) {
	_, err := Load("../../testdata/specs/swagger-2.0-ref-into-paths.json", anyRule)
	want := "swagger-2.0-ref-into-paths.json:10:79: paths > /b > get > responses > default > schema > $ref: this $ref into #/paths cannot be converted to OpenAPI 3"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Load = %v, want %q", err, want)
	}
}
