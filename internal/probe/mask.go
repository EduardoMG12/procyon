package probe

import (
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Evidence never shows a secret: a test account's token, a password, or
// the personal data an anonymous caller got.

// mask hides every token in s, in each of its forms, so evidence never
// shows a credential, even one the API echoes back.
func mask(s string, tokens ...string) string {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		for _, form := range forms(token) {
			s = strings.ReplaceAll(s, form, "****")
		}
	}
	return s
}

// forms are the ways a token can be written in an answer: as it is,
// URL-encoded and JSON-escaped (a JSON string escapes <, > and &, and
// PHP's escapes / too).
func forms(token string) []string {
	return []string{token, url.QueryEscape(token), jsonEscaped(token), strings.ReplaceAll(token, "/", `\/`)}
}

// jsonEscaped is token as encoding/json writes it inside a string.
func jsonEscaped(token string) string {
	quoted, _ := json.Marshal(token) // a string always marshals
	return string(quoted[1 : len(quoted)-1])
}

// excerpt is the start of a body for evidence, every token masked. Masked
// before it is cut: a token across the cut would otherwise leave its first
// characters unmasked.
func (r *runner) excerpt(body string) string {
	masked := mask(body, r.tokens...)
	if len(masked) <= maxBody {
		return masked
	}
	end := maxBody
	for end > 0 && !utf8.RuneStart(masked[end]) {
		end-- // never cut a character in half
	}
	return masked[:end]
}

// maskCut masks values in excerpt, the start of an answer already cut for
// evidence. A token is masked before the cut (runner.excerpt), but a list
// of a thousand customers would then be searched a thousand times; values
// are masked in the excerpt only, and the start of a value the cut split
// in two is dropped from its end.
func maskCut(excerpt string, values []string) string {
	excerpt = mask(excerpt, values...)
	for _, v := range values {
		for _, form := range forms(v) {
			for n := len(form) - 1; n > 0; n-- { // a whole form is masked already
				if strings.HasSuffix(excerpt, form[:n]) {
					excerpt = excerpt[:len(excerpt)-n]
					break
				}
			}
		}
	}
	return excerpt
}
