package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestChanged(t *testing.T) {
	spec, err := Load("../vulnapi/openapi.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	// The base has no /health, and NoteInput's title allowed 200 characters.
	base, err := Load("../../testdata/specs/runtime-notes-base.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(func(yield func(string) bool) {
		changed, _ := spec.Changed(base)
		for op := range changed {
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
	if changed, _ := spec.Changed(spec); len(changed) != 0 {
		t.Errorf("a spec against itself: %v, want nothing", changed)
	}
}

// Every schema refers to the next layer twice: inlining would expand 2^30
// copies; hashing each node once stays linear.
func TestChangedIsLinearOnSharedSchemas(t *testing.T) {
	var b strings.Builder
	b.WriteString("openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n          content: {application/json: {schema: {$ref: '#/components/schemas/L0'}}}\ncomponents:\n  schemas:\n")
	for i := range 30 {
		fmt.Fprintf(&b, "    L%d: {type: object, properties: {a: {$ref: '#/components/schemas/L%d'}, b: {$ref: '#/components/schemas/L%d'}}}\n", i, i+1, i+1)
	}
	b.WriteString("    L30: {type: string}\n")
	path := filepath.Join(t.TempDir(), "deep.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := Load(path, anyRule)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan map[string]bool)
	go func() { changed, _ := spec.Changed(spec); done <- changed }()
	select {
	case changed := <-done:
		if len(changed) != 0 {
			t.Errorf("changed = %v, want nothing", changed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Changed took over 10s on 30 layers of shared schemas")
	}
}

func TestChangedIsConservativeOnSplitSpecs(t *testing.T) {
	spec, err := Load("../../testdata/specs/split/api.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	changed, note := spec.Changed(spec)
	if len(changed) == 0 || !strings.Contains(note, "split across files") {
		t.Errorf("changed %v, note %q; want everything changed and a note", changed, note)
	}
}
