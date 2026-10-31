package loader

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// JSON allows, in a string, characters that kin-openapi's YAML parser
// refuses (DEL, C1 controls, U+FFFE) or reads as line breaks (NEL, U+2028),
// and kin-openapi reads every spec as YAML. A spec with one of them loads,
// keeps its text, and points at the same places as the same spec with an
// ordinary character instead: GET /a sits after the character on its line,
// GET /b on the next line.
func TestJSONWithCharactersYAMLCannotHold(t *testing.T) {
	openapi := func(char string) map[string]string {
		return map[string]string{"api.json": `{"openapi": "3.0.3",` + "\n" +
			`"info": {"title": "a` + char + `b", "version": "1"}, "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}},` + "\n" +
			`"/b": {"get": {"responses": {"200": {"description": "ok"}}}}}}` + "\n"}
	}
	// Converted Swagger 2.0 is indented JSON, each key on its own line: no
	// escape comes before a key, so this case only proves the spec loads.
	swagger := func(char string) map[string]string {
		return map[string]string{"api.json": `{"swagger": "2.0", "info": {"title": "a` + char + `b", "version": "1"},` +
			` "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}`}
	}
	// A file read through a $ref goes through the same parser.
	split := func(char string) map[string]string {
		return map[string]string{
			"api.yaml": "openapi: 3.0.3\ninfo: {title: t, version: \"1\"}\npaths:\n  /b:\n    $ref: ./b.json\n",
			"b.json":   `{"description": "a` + char + `b", "get": {"responses": {"200": {"description": "ok"}}}}`,
		}
	}
	for _, char := range []string{"\u007f", "\u0080", "\u0085", "\u009f", "\u2028", "\u2029", "\ufffe", "\uffff"} {
		for name, spec := range map[string]func(string) map[string]string{"openapi": openapi, "swagger": swagger, "split": split} {
			got, text := loadLocations(t, spec(char))
			want, _ := loadLocations(t, spec("x"))
			if !maps.Equal(got, want) {
				t.Errorf("%s with %q: operations at %v, want %v", name, char, got, want)
			}
			if !strings.Contains(text, "a"+char+"b") {
				t.Errorf("%s with %q: the text read is %q, want it to keep the character", name, char, text)
			}
		}
	}
}

// loadLocations writes files to a directory and loads its api.json or
// api.yaml. It returns each operation's place (file:line:column) and the
// text kin-openapi read for the title or the path item's description.
func loadLocations(t *testing.T, files map[string]string) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	spec := ""
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(name, "api.") {
			spec = filepath.Join(dir, name)
		}
	}
	loaded, err := Load(spec, anyRule)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	places := map[string]string{}
	for _, op := range loaded.Operations() {
		loc := op.Location
		places[op.Method+" "+op.Path] = fmt.Sprintf("%s:%d:%d", filepath.Base(loc.File), loc.Line, loc.Column)
	}
	text := loaded.Doc().Info.Title
	if item := loaded.Doc().Paths.Find("/b"); item != nil && item.Description != "" {
		text = item.Description
	}
	return places, text
}
