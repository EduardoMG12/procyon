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
