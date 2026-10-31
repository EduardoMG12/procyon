package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadListsOperationsInOrder(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, op := range spec.Operations() {
		public := ""
		if op.Public {
			public = " public"
		}
		got = append(got, op.Method+" "+op.Path+public)
	}
	want := []string{
		"GET /health public",
		"POST /login public",
		"GET /me",
		"GET /menu",
		"GET /notes",
		"POST /notes",
		"DELETE /notes/{id}",
		"GET /notes/{id}",
		"PUT /notes/{id}",
		"GET /orders",
		"GET /orders/{orderId}",
		"GET /owner-notes", "GET /shop public", "GET /tracking/{trackingId} public",
	}
	if !slices.Equal(got, want) {
		t.Errorf("operations = %q, want %q", got, want)
	}
	health := spec.Operations()[0]
	if health.Location.Line != 63 || !strings.HasSuffix(health.Location.File, "openapi.yaml") {
		t.Errorf("GET /health location = %+v, want openapi.yaml line 63", health.Location)
	}
	if len(spec.Sources()[health.Location.File]) == 0 {
		t.Error("Sources has no lines for the spec")
	}
}

func TestLoadRefusesWhatRunRefuses(t *testing.T) {
	for _, name := range []string{"invalid-yaml.yaml", "ignore-no-reason.yaml", "ref-remote.yaml"} {
		if _, err := Load("../../testdata/specs/"+name, anyRule); err == nil {
			t.Errorf("Load(%s) succeeded, want the error Run gives", name)
		}
	}
}

func TestOperationCredentials(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-credentials.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/default":       "header Authorization Bearer ",
		"/basic":         "header Authorization Basic ",
		"/key":           "header X-API-Key ",
		"/cookie":        "cookie session ",
		"/oauth":         "header Authorization Bearer ",
		"/both-then-key": "header X-API-Key ", // two schemes at once cannot be filled with one token
		"/mtls":          "none",
		"/none":          "none",
		"/param":         "header x-access-token ",
	}
	for _, op := range spec.Operations() {
		got := "none"
		if c := op.Credential; c != nil {
			got = c.In + " " + c.Name + " " + c.Prefix
		}
		if got != want[op.Path] {
			t.Errorf("%s credential = %q, want %q", op.Path, got, want[op.Path])
		}
	}
}

func TestOperationExampleBodies(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		want, needs := "", false
		if op.Path == "/login" {
			want, needs = "", true // a schema with no example
		} else if op.Method == "POST" || op.Method == "PUT" {
			want, needs = `{"body":"bread, coffee","title":"Shopping list"}`, true
		}
		if string(op.Body) != want || op.NeedsBody != needs {
			t.Errorf("%s %s: body %s, needs %v; want %s, %v", op.Method, op.Path, op.Body, op.NeedsBody, want, needs)
		}
	}
}

func TestOperationBodyFields(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		if op.Method != "POST" || op.Path != "/notes" {
			continue
		}
		var got []string
		for _, f := range op.Fields {
			max := "none"
			if f.MaxLength != nil {
				max = fmt.Sprint(*f.MaxLength)
			}
			got = append(got, fmt.Sprintf("%s %v required=%v max=%s", f.Name, f.Types, f.Required, max))
		}
		want := []string{"body [string] required=false max=10000", "title [string] required=true max=100"}
		if !slices.Equal(got, want) {
			t.Errorf("fields = %q, want %q", got, want)
		}
	}
}

func TestExampleBodyFromPropertyExamples(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-vampi-like.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations() {
		switch op.Method + " " + op.Path {
		case "PUT /users/{username}/password":
			if string(op.Body) != `{"password":"new-password"}` || !op.NeedsAuth {
				t.Errorf("password body %s, needs auth %v", op.Body, op.NeedsAuth)
			}
		case "GET /users":
			if op.NeedsAuth {
				t.Error("GET /users has no security, NeedsAuth is true")
			}
		}
	}
}

// Only required query parameters are listed, credentials left out, each
// with the spec's example when it gives one.
func TestOperationRequiredQuery(t *testing.T) {
	spec, err := Load("../../testdata/specs/runtime-query.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, op := range spec.Operations() {
		for _, q := range op.Query {
			got[op.Path] = append(got[op.Path], q.Name+"="+q.Example)
		}
	}
	// The operation's own parameters come before the path's; /signed's
	// only one is where its security scheme puts the token.
	want := []string{"q=raccoon", "page=2", "kind=alpha", "owner="}
	if !slices.Equal(got["/search"], want) || len(got["/signed"]) != 0 {
		t.Errorf("query = %q, want /search %q and nothing for /signed", got, want)
	}
}

// anyRule loads specs whatever rules their ignores name: which rules exist
// is internal/lint's business, tested there.
var anyRule = Options{KnownRule: func(string) bool { return true }}

// A JSON spec saved with a byte order mark loads, like a YAML one.
func TestLoadSkipsAByteOrderMark(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openapi.json")
	spec := `{"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}`
	if err := os.WriteFile(path, append([]byte("\xef\xbb\xbf"), spec...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, Options{}); err != nil {
		t.Errorf("Load: %v", err)
	}
}

func TestServerPath(t *testing.T) {
	tests := map[string]string{
		`openapi: 3.0.3
servers: [{url: /b2b/v2}]`: "/b2b/v2",
		`openapi: 3.0.3
servers: [{url: "https://shop.example/{version}", variables: {version: {default: v1}}}, {url: /other}]`: "/v1",
		`openapi: 3.0.3
servers: [{url: "http://localhost:8080"}]`: "",
		`openapi: 3.0.3`: "",
		`swagger: "2.0"
host: shop.example
basePath: /api`: "/api",
	}
	for head, want := range tests {
		path := filepath.Join(t.TempDir(), "openapi.yaml")
		text := head + "\ninfo: {title: t, version: \"1\"}\npaths: {}\n"
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		spec, err := Load(path, anyRule)
		if err != nil {
			t.Fatalf("%s: %v", head, err)
		}
		if got := spec.ServerPath(); got != want {
			t.Errorf("%s: ServerPath() = %q, want %q", head, got, want)
		}
	}
}
