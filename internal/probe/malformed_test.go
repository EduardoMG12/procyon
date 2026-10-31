package probe

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

func TestMutations(t *testing.T) {
	ten := uint64(10)
	str := []string{"string"}
	tests := []struct {
		name    string
		example string
		fields  []loader.Field
		want    []string // what, then body, for each mutation
	}{
		{"every kind", `{"count": 1, "kind": "a", "name": "x"}`, []loader.Field{
			{Name: "count", Types: []string{"integer"}},
			{Name: "kind", Types: str, Enum: true},
			{Name: "name", Types: str, Required: true, MaxLength: &ten},
		}, []string{
			"name as a number", `{"count":1,"kind":"a","name":42}`,
			"without the required name", `{"count":1,"kind":"a"}`,
			"kind outside its enum", `{"count":1,"kind":"procyon-not-in-enum","name":"x"}`,
			"name of 11 characters (maxLength 10)", `{"count":1,"kind":"a","name":"aaaaaaaaaaa"}`,
		}},
		{"a number field gets text", `{"count": 1}`, []loader.Field{{Name: "count", Types: []string{"integer", "null"}}},
			[]string{"count as text", `{"count":"not-a-number"}`}},
		{"string or integer gets a boolean", `{"id": 1}`, []loader.Field{{Name: "id", Types: []string{"string", "integer"}}},
			[]string{"id as a boolean", `{"id":true}`}},
		{"unknown types are never given a wrong type", `{"any": 1}`, []loader.Field{{Name: "any"}}, nil},
		{"a required field the example lacks is not removed", `{"name": "x"}`, []loader.Field{
			{Name: "id", Required: true}, {Name: "name"},
		}, nil},
		{"an integer enum is not given a string", `{"level": 1}`, []loader.Field{{Name: "level", Types: []string{"integer"}, Enum: true}},
			[]string{"level as text", `{"level":"not-a-number"}`}},
		{"not an object", `[1, 2]`, []loader.Field{{Name: "x", Types: str}}, nil},
	}
	for _, tt := range tests {
		var got []string
		for _, m := range mutations([]byte(tt.example), tt.fields) {
			got = append(got, m.what, string(m.body))
			if m.allowed {
				t.Errorf("%s: %q is allowed, want forbidden by the spec", tt.name, m.what)
			}
		}
		if len(got) != len(tt.want) {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
				break
			}
		}
	}
	// No maxLength: one very long string instead, which the spec allows.
	got := mutations([]byte(`{"note": "x"}`), []loader.Field{{Name: "note", Types: str}})
	if len(got) != 2 || got[1].what != "note of 100000 characters" || len(got[1].body) < 100000 || !got[1].allowed {
		t.Errorf("very long string: %d mutations, last %q", len(got), got[len(got)-1].what)
	}
}

// A 2xx the spec documents as an error answer is a refusal, not an
// acceptance (PRC104): /register's 202 is "already registered, or a field
// is missing". When the example itself gets one (/login's wrong password),
// the malformed bodies are not judged, as after a 4xx. A 2xx the spec
// documents as a success (/notes's "accepted and saved later"), or one it
// does not document (/upload's 202), is still accepted.
func TestPRC104TrustsTheSpecsErrorAnswers(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		_, valid := body["pass"].(string)
		switch {
		case userOf(r) == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/login":
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"message": "sorry, invalid login"}`))
		case valid:
			w.Write([]byte(`{"token": "t-1"}`))
		default:
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"message": "missing user or pass"}`))
		}
	})
	rep := runOn(t, "../../testdata/specs/prc104-error-answers.yaml", handler, Options{})
	if got, want := findingKeys(rep), []string{"PRC104 POST /notes", "PRC104 POST /upload"}; !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
	note := "POST /login: malformed input not tested: the spec's own example, sent as A, already gets 202, " +
		"which the spec documents as an error answer"
	if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return n.Message == note }) {
		t.Errorf("notes %v, want %q", rep.Notes, note)
	}
}
