package loader

import (
	"slices"
	"strings"
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

// An ignore on an operation may name one field of its response, found
// through $refs, allOf and list items; the note about it says which.
func TestIgnoreNamesAField(t *testing.T) {
	spec, err := Load("../../testdata/specs/ignore-field.yaml", anyRule)
	if err != nil {
		t.Fatal(err)
	}
	var notes []string
	for _, n := range report.New(nil, nil, spec.Ignores(), report.Options{}).Notes {
		notes = append(notes, n.Message)
	}
	want := []string{
		"ignore of PRC106 on GET /shop (field phone) matches no finding; remove it",
		"ignore of PRC106 on GET /shop (field reviews.author.email) matches no finding; remove it",
	}
	if !slices.Equal(notes, want) {
		t.Errorf("notes:\n%q\nwant:\n%q", notes, want)
	}
}

// A field the response schema does not describe, or one written where
// there is no response, stops the run: a typo must never ignore something.
func TestIgnoreOfAnUnknownFieldIsAnError(t *testing.T) {
	for file, want := range map[string]string{
		"ignore-field-unknown.yaml":          `ignore-field-unknown.yaml:8:7: GET /shop: x-procyon-ignore: entry 1 (PRC106): field "reviews.emial" is no field of the operation's response schema`,
		"ignore-field-not-a-string.yaml":     `ignore-field-not-a-string.yaml:8:7: GET /shop: x-procyon-ignore: entry 1 (PRC106): field "[phone]" is no field`,
		"ignore-field-not-on-operation.yaml": `ignore-field-not-on-operation.yaml:5:1: x-procyon-ignore: entry 1 (PRC106): field names a field of an operation's response`,
	} {
		_, err := Load("../../testdata/specs/"+file, anyRule)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Load(%s) = %v, want an error containing %q", file, err, want)
		}
	}
}
