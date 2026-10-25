package lint

import (
	"slices"
	"testing"
)

func TestChanged(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The base has no /health, and NoteInput's title allowed 200 characters.
	base, err := Load("../../testdata/specs/runtime-notes-base.yaml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(func(yield func(string) bool) {
		for op := range spec.Changed(base) {
			if !yield(op) {
				return
			}
		}
	})
	// POST /notes and PUT /notes/{id} reference NoteInput through $ref.
	want := []string{"GET /health", "POST /notes", "PUT /notes/{id}"}
	if !slices.Equal(got, want) {
		t.Errorf("changed = %q, want %q", got, want)
	}
	if changed := spec.Changed(spec); len(changed) != 0 {
		t.Errorf("a spec against itself: %v, want nothing", changed)
	}
}
