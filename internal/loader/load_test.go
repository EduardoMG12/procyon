package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goccy/go-yaml refuses a |+ block with no content, which is valid YAML. An
// OpenAPI 3 spec with one loads, with the block's value (one line break)
// and its locations; a Swagger 2.0 one, which needs goccy's syntax tree to
// be converted, is still refused with goccy's message.
func TestKeepBlockWithoutContent(t *testing.T) {
	spec, err := Load("../../testdata/specs/valid-keep-block.yaml", anyRule)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	op := spec.Doc().Paths.Find("/orders").Get
	example := op.Responses.Status(200).Value.Content.Get("application/json").Schema.Value.Example
	if example != "\n" {
		t.Errorf("example = %q, want one line break", example)
	}
	if loc := spec.Operations()[0].Location; loc.Line != 7 || loc.Column != 5 {
		t.Errorf("GET /orders at %d:%d, want 7:5", loc.Line, loc.Column)
	}

	swagger := filepath.Join(t.TempDir(), "swagger.yaml")
	body := "swagger: \"2.0\"\ninfo:\n  title: t\n  version: \"1\"\n" +
		"paths:\n  /a:\n    get:\n      description: |+\n\n      responses:\n        \"200\":\n          description: ok\n"
	if err := os.WriteFile(swagger, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(swagger, anyRule); err == nil || !strings.Contains(err.Error(), "swagger.yaml:10:7: could not find multi-line content") {
		t.Errorf("Load(Swagger 2.0) = %v, want goccy's error at 10:7", err)
	}
}
