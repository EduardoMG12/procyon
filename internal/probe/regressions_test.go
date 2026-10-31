package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/EduardoMG12/procyon/internal/report"
)

// writeSpec writes a spec into a temporary directory and returns its path.
func writeSpec(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const bearerSpec = `openapi: 3.0.3
info: {title: t, version: "1"}
security: [{bearer: []}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
paths:
`

// A harvested value with a space goes out escaped once: /users/Ana%20Maria,
// which the server reads as "Ana Maria", not Ana%2520Maria.
func TestPathValuesAreEscapedOnce(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /users:
    get:
      responses: {"200": {description: ok}}
  /users/{name}:
    parameters: [{name: name, in: path, required: true, schema: {type: string}}]
    get:
      responses: {"200": {description: ok}}
`)
	var mu sync.Mutex
	var paths []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/users" {
			w.Write([]byte(`[{"name": "Ana Maria"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	runOn(t, spec, handler, Options{})
	if !slices.Contains(paths, "/users/Ana Maria") {
		t.Errorf("paths requested %q, want /users/Ana Maria", paths)
	}
}

// When the server refuses B's changed body, B sends the example as is; if
// A's object already holds it, a 2xx proves nothing (here B's write is a
// silent no-op, the way UPDATE ... WHERE owner = caller is).
func TestFallbackWriteOfAnExampleAHoldsIsNotAFinding(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /items/{id}:
    parameters: [{name: id, in: path, required: true, schema: {type: string}}]
    get:
      responses: {"200": {description: ok}}
    put:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string, maxLength: 10}
            example: {name: box}
      responses: {"204": {description: ok}}
`)
	var mu sync.Mutex
	name := "box"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		who := userOf(r)
		switch {
		case who == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path != "/items/a1":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET" && who == "alice":
			fmt.Fprintf(w, `{"id": "a1", "name": %q}`, name)
		case r.Method == "GET":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "PUT":
			var in struct{ Name string }
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Name == "" || len(in.Name) > 10 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if who == "alice" {
				name = in.Name
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
	rep := runOn(t, spec, handler, Options{IDs: map[string][]string{"id": {"a1"}}})
	for _, f := range findingsOf(rep, "PRC102") {
		t.Errorf("PRC102 on %s, want none: B's write changed nothing", f.Operation)
	}
}

// A spec with more operations than the old fixed budget of 1000 requests
// could cover still runs to the end.
func TestBudgetGrowsWithTheSpec(t *testing.T) {
	var b strings.Builder
	b.WriteString(bearerSpec)
	for i := range 350 {
		fmt.Fprintf(&b, "  /r%d:\n    get:\n      responses: {\"200\": {description: ok}}\n", i)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userOf(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{}`))
	})
	runOn(t, writeSpec(t, b.String()), handler, Options{}) // runOn fails the test on an error
}

// A required query parameter no response shows and the spec gives no
// example for is never sent missing: the operation is a note, and a
// skipped row.
func TestUnfilledQueryParameterIsANote(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /notes:
    get:
      parameters: [{name: owner, in: query, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`)
	var sent []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.URL.RequestURI())
	})
	rep := runOn(t, spec, handler, Options{})
	want := "GET /notes not tested: no value for query parameter owner in A's responses; declare one under test.ids in .procyon.yaml"
	if len(sent) != 0 || !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return n.Message == want }) ||
		len(rep.Matrix) != 1 || rep.Matrix[0].A.Outcome != report.Skipped {
		t.Errorf("sent %q, notes %v, matrix %+v; want nothing sent, the note and a skipped row", sent, rep.Notes, rep.Matrix)
	}
}
