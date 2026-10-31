package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An OpenAPI 3.1 schema may hold keywords JSON Schema does not define,
// wherever the schema sits; a 3.0 one may not. The fixture has one in every
// kind of place a schema can be: a place the walk missed would be refused.
func TestOpenAPI31SchemasMayHaveUnknownKeywords(t *testing.T) {
	spec, err := Load("../../testdata/specs/valid-3.1-unknown-keywords.yaml", anyRule)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	order := spec.Doc().Components.Schemas["Order"].Value
	if _, kept := order.Extensions["x-note"]; !kept {
		t.Error("the x-note extension was dropped with the unknown keywords")
	}

	path := filepath.Join(t.TempDir(), "api.yaml")
	body := "openapi: 3.0.3\ninfo: {title: t, version: \"1\"}\npaths: {}\n" +
		"components:\n  schemas:\n    Order: {type: string, regex: \"^o\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, anyRule); err == nil || !strings.Contains(err.Error(), "extra sibling fields: [regex]") {
		t.Errorf("Load(3.0) = %v, want the unknown keyword refused", err)
	}
}

// Versions Procyon does not read are refused by name, not linted as 3.0;
// a 3.2 spec loads, and a field new in 3.2 that kin-openapi does not know
// says so.
func TestOpenAPIVersions(t *testing.T) {
	tests := []struct{ version, extra, wantErr string }{
		{"3.0.3", "", ""},
		{"3.1.1", "", ""},
		{"3.2.0", "", ""},
		{"3.3.0", "", `openapi "3.3.0" is not a version Procyon knows`},
		{"4.0.0", "", `openapi "4.0.0" is not a version Procyon knows`},
		{"3.1.9", "", `openapi "3.1.9" is not a version Procyon knows`}, // a patch kin-openapi does not list
		{"3.2.0", "tags: [{name: a, kind: nav}]\n", "invalid spec (OpenAPI 3.2 is only partly supported"},
		{"3.1.0", "tags: [{name: a, kind: nav}]\n", "invalid spec: invalid tags"},
	}
	for _, tt := range tests {
		path := filepath.Join(t.TempDir(), "api.yaml")
		body := "openapi: " + tt.version + "\ninfo: {title: t, version: \"1\"}\npaths: {}\n" + tt.extra
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path, anyRule)
		switch {
		case tt.wantErr == "" && err != nil:
			t.Errorf("%s %q: Load = %v, want it loaded", tt.version, tt.extra, err)
		case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
			t.Errorf("%s %q: Load = %v, want %q", tt.version, tt.extra, err, tt.wantErr)
		}
	}
}
