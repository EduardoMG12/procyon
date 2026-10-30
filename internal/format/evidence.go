package format

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/EduardoMG12/procyon/internal/report"
)

// How every format writes a runtime finding's evidence.

// exchangeLine is "B: GET /notes/1 → 200", or "→ no answer" for a request
// that timed out.
func exchangeLine(e report.Exchange) string {
	if e.Status == 0 {
		return fmt.Sprintf("%s: %s %s → no answer", e.Caller, e.Method, e.URL)
	}
	return fmt.Sprintf("%s: %s %s → %d", e.Caller, e.Method, e.URL, e.Status)
}

// flatten joins a body's lines and spaces, so an excerpt never breaks the
// layout.
func flatten(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// visible shows hidden characters as escapes: \x1b up to U+00FF, \u202e
// up to U+FFFF, \U000e0041 beyond. Text from a spec or from an API's
// answer must not reach a terminal or a rendered page raw: an escape
// sequence in it could change colours, rewrite earlier lines or, through
// OSC 52, write to the reader's clipboard; a bidi control could reorder
// the text around it ("Trojan Source"); an invisible character could make
// two names look the same.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case !hidden(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r < 0x10000:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			fmt.Fprintf(&b, "\\U%08x", r)
		}
	}
	return b.String()
}

// hidden reports whether r acts on the screen instead of showing as
// itself: a control character (C0, DEL and C1; tab aside) or a format
// character, Unicode category Cf. Cf holds every bidi control (U+202A to
// U+202E, U+2066 to U+2069, U+200E, U+200F, U+061C) and the invisible
// characters (zero-width space U+200B, joiners U+200C and U+200D, word
// joiner U+2060, BOM U+FEFF, soft hyphen U+00AD, tag characters), and it
// grows with Unicode as Go updates its tables. The cost: an emoji built
// with zero-width joiners, such as the family emoji (man, joiner, woman,
// joiner, girl), shows as its parts with \u200d between them. Accents,
// CJK and other emoji are letters or symbols, not Cf, and show as they
// are.
func hidden(r rune) bool {
	return r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r))
}
