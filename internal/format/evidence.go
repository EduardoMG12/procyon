package format

import (
	"fmt"
	"strings"

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

// visible shows control characters as \x1b and the like. Text from a spec
// or from an API's answer must not reach a terminal raw: an escape sequence
// in it could change colours, rewrite earlier lines or, through OSC 52,
// write to the reader's clipboard. Tabs are kept.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)) {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
