package loader

import (
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/report"
)

// Ignores are read in a stable order, so the notes about unused ones come
// out in the same order on every run: path-level servers by path, security
// schemes by name, though both live in maps.
func TestIgnoresInAStableOrder(t *testing.T) {
	spec, err := Load("../../testdata/specs/ignores-order.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	var notes []string
	for _, n := range report.New(nil, nil, spec.Ignores(), report.Options{}).Notes {
		notes = append(notes, n.Message)
	}
	want := []string{
		"ignore of PRC004 on server https://a.example.com matches no finding; remove it",
		"ignore of PRC004 on server https://b.example.com matches no finding; remove it",
		"ignore of PRC003 on security scheme alpha matches no finding; remove it",
		"ignore of PRC003 on security scheme beta matches no finding; remove it",
	}
	if !slices.Equal(notes, want) {
		t.Errorf("notes:\n%q\nwant:\n%q", notes, want)
	}
}
