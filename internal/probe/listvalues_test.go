package probe

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
)

// A value inside a JSON list ({"tags": ["x"]}) is a value like any other,
// both ways: A's data that B's answer holds only in a list is still A's
// data (PRC102), and a value B's own responses showed only in a list is
// still one B saw, so it proves nothing.
func TestValuesInsideListsCount(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /me:
    get:
      responses: {"200": {description: ok}}
  /popular:
    get:
      responses: {"200": {description: ok}}
  /notes:
    get:
      responses: {"200": {description: ok}}
  /notes/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`)
	for _, tt := range []struct {
		name    string
		note    string // alice's note n1, which any account may read
		finding bool
	}{
		{"A's data only in a list", `{"id": "n1", "tags": ["alice-private"]}`, true},
		{"what every account sees, in a list", `{"id": "n1", "label": "everyone-sees"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				who := userOf(r)
				switch {
				case who == "":
					w.WriteHeader(http.StatusUnauthorized)
				case r.URL.Path == "/me":
					fmt.Fprintf(w, `{"username": %q}`, who)
				case r.URL.Path == "/popular": // the same for every account
					w.Write([]byte(`{"labels": ["everyone-sees"]}`))
				case r.URL.Path == "/notes" && who == "alice":
					w.Write([]byte(`[{"id": "n1"}]`))
				case r.URL.Path == "/notes":
					w.Write([]byte(`[{"id": "n2"}]`))
				case r.URL.Path == "/notes/n1": // vulnerable: no owner check
					w.Write([]byte(tt.note))
				case r.URL.Path == "/notes/n2":
					w.Write([]byte(`{"id": "n2"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			rep := runOn(t, spec, handler, Options{})
			found := slices.Contains(findingKeys(rep), "PRC102 GET /notes/{id}")
			if found != tt.finding {
				t.Errorf("PRC102 on GET /notes/{id} = %v, want %v (findings %q)", found, tt.finding, findingKeys(rep))
			}
		})
	}
}
