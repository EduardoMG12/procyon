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

// PRC108: B searches a list with its own filter value, never A's. A search
// that ignores the filter and returns every account's objects is reported;
// one that scopes the list to the caller is not.
func TestPRC108SearchesWithBsOwnFilter(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /me:
    get:
      responses: {"200": {description: ok}}
  /customers:
    get:
      parameters: [{name: username, in: query, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`)
	for _, tt := range []struct {
		name    string
		ignores bool // the server ignores the owner filter
		finding bool
	}{
		{"ignores the filter", true, true},
		{"scopes to the caller", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var ownersB []string // the owner value B searched by
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				who := userOf(r)
				if who == "" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch {
				case r.URL.Path == "/me":
					fmt.Fprintf(w, `{"username": %q}`, who)
				case r.URL.Path == "/customers":
					if who == "bob" {
						ownersB = append(ownersB, r.URL.Query().Get("username"))
					}
					if tt.ignores { // every customer, whatever the filter asked
						w.Write([]byte(`[{"id": "c1", "username": "alice"}, {"id": "c2", "username": "bob"}]`))
						return
					}
					fmt.Fprintf(w, `[{"id": "c-%s", "username": %q}]`, who, who) // only the caller's
				}
			})
			rep := runOn(t, spec, handler, Options{})
			found := slices.Contains(findingKeys(rep), "PRC108 GET /customers")
			if found != tt.finding {
				t.Errorf("PRC108 on GET /customers = %v, want %v (findings %q)", found, tt.finding, findingKeys(rep))
			}
			// PRC108 runs first and always with B's own value; a later
			// PRC102 search (the scoped case) may use A's.
			if len(ownersB) == 0 || ownersB[0] != "bob" {
				t.Errorf("B first searched by %q, want its own [bob] for PRC108", ownersB)
			}
		})
	}
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

// An optional query parameter that names an object is filled the way a
// required one is, and B is tested on A's object (PRC102): picture_id is
// named like an ID and /pictures shows one; username is declared under
// test.ids. One named like an ID that no response shows is a note, and so
// is a required one only the spec's example fills. A filter that names no
// object (status) is never sent, though a response shows one and the spec
// gives an example.
func TestOptionalQueryParametersThatNameAnObject(t *testing.T) {
	var statusSent bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		statusSent = statusSent || q.Has("status")
		switch {
		case userOf(r) == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/pictures":
			fmt.Fprintf(w, `[{"picture_id": "pic-%s-7f3a", "title": "%s's cat"}]`, userOf(r), userOf(r))
		case r.URL.Path == "/picture" && q.Has("picture_id"): // anyone's picture, by ID
			owner := strings.Split(q.Get("picture_id"), "-")[1]
			fmt.Fprintf(w, `{"picture_id": %q, "title": "%s's cat"}`, q.Get("picture_id"), owner)
		case r.URL.Path == "/note" && q.Has("username"): // anyone's note, by name
			fmt.Fprintf(w, `{"username": %q, "text": "the private note of %s"}`, q.Get("username"), q.Get("username"))
		case r.URL.Path == "/products":
			w.Write([]byte(`[{"id": "p1", "status": "sold"}]`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	rep := runOn(t, "../../testdata/specs/runtime-optional-query.yaml", handler, Options{IDs: map[string][]string{"username": {"alice"}}})
	if got, want := findingKeys(rep), []string{"PRC102 GET /picture", "PRC102 GET /note"}; !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
	for _, note := range []string{
		"GET /report: query parameter reportId not sent: it names an object and no response of A's shows one; " +
			"declare one under test.ids in .procyon.yaml",
		"GET /mechanic-report: not tested as B: query parameter report_id was sent with the spec's example, " +
			"which names no object of A's; declare one of A's under test.ids in .procyon.yaml",
	} {
		if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return n.Message == note }) {
			t.Errorf("notes %v, want %q", rep.Notes, note)
		}
	}
	if statusSent {
		t.Error("the optional filter status was sent")
	}
}
