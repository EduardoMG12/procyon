package probe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMask(t *testing.T) {
	got := mask(`{"echo":"a+b/c"} http://x/?k=a%2Bb%2Fc`, "a+b/c", "")
	if want := `{"echo":"****"} http://x/?k=****`; got != want {
		t.Errorf("mask = %q, want %q", got, want)
	}
}

// A token the API echoes JSON-escaped is masked too.
func TestMaskJSONEscapedTokens(t *testing.T) {
	token := "a/b<c>&d"
	for _, echoed := range []string{`"a\/b<c>&d"`, `"a/b\u003cc\u003e\u0026d"`} {
		if got := mask(echoed, token); strings.Contains(got, "a/b") || strings.Contains(got, "a\\/b") {
			t.Errorf("mask(%s) = %s, want the token hidden", echoed, got)
		}
	}
}

// An excerpt never ends in the middle of a character.
func TestExcerptCutsOnACharacterBoundary(t *testing.T) {
	r := &runner{}
	body := strings.Repeat("a", maxBody-1) + "é" // é takes two bytes: the cut falls inside it
	got := r.excerpt(body)
	if !utf8.ValidString(got) || len(got) != maxBody-1 {
		t.Errorf("excerpt is %d bytes, valid UTF-8 %v; want %d and valid", len(got), utf8.ValidString(got), maxBody-1)
	}
}

// Values are masked in the excerpt, after the cut: a value the cut split
// in two leaves nothing of itself, in any form.
func TestMaskCut(t *testing.T) {
	for excerpt, want := range map[string]string{
		`{"email": "ana@example.com", "phone": "+55 11`: `{"email": "****", "phone": "`,
		`{"cnpj": "12.345.678\/00`:                      `{"cnpj": "`,
		`{"name": "Ana"}`:                               `{"name": "Ana"}`,
	} {
		if got := maskCut(excerpt, []string{"ana@example.com", "+55 11 3333-4444", "12.345.678/0001-90"}); got != want {
			t.Errorf("maskCut(%s) = %s, want %s", excerpt, got, want)
		}
	}
}
