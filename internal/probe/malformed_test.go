package probe

import (
	"testing"

	"github.com/EduardoMG12/procyon/internal/loader"
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
