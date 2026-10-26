package test

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// The environment variables that hold the test accounts' tokens.
const (
	EnvTokenA = "PROCYON_USER_A_TOKEN"
	EnvTokenB = "PROCYON_USER_B_TOKEN"
)

// caller is who sends a request: a test account with its token, or the
// anonymous caller with none.
type caller struct {
	name  string // "A", "B" or "anonymous"
	token string
}

var anonymous = caller{name: "anonymous"}

// authorize puts token into req the way cred says. The token is the bare
// value: Procyon adds the "Bearer " or "Basic " prefix the scheme needs.
func authorize(req *http.Request, cred *lint.Credential, token string) {
	if cred == nil || token == "" {
		return
	}
	switch cred.In {
	case "header":
		req.Header.Set(cred.Name, cred.Prefix+token)
	case "query":
		q := req.URL.Query()
		q.Set(cred.Name, token)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{Name: cred.Name, Value: token})
	}
}

// mask hides every token in s, as written and as URL-encoded, so evidence
// never shows a credential, even one the API echoes back.
func mask(s string, tokens ...string) string {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		s = strings.ReplaceAll(s, token, "****")
		if escaped := url.QueryEscape(token); escaped != token {
			s = strings.ReplaceAll(s, escaped, "****")
		}
	}
	return s
}
