package format

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
)

// How every format keeps text from a spec or an API's answer from acting on
// the screen it is read on.

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

// escapeHidden writes the hidden characters of encoded JSON as \u escapes.
// encoding/json escapes C0 only; DEL, C1, bidi controls and invisible
// characters stay raw, and would act on whoever reads the file in a
// terminal or a CI log. Unlike visible, this keeps every value: a script
// decodes the same strings. The only raw control left in encoded JSON is
// the newline of the indentation, outside any string, and it stays.
func escapeHidden(encoded string) string {
	var b strings.Builder
	for _, r := range encoded {
		if r == '\n' || !hidden(r) {
			b.WriteRune(r)
			continue
		}
		// A character beyond U+FFFF is written as a UTF-16 surrogate pair,
		// as JSON requires.
		for _, unit := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u%04x`, unit)
		}
	}
	return b.String()
}
