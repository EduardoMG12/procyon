package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
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

// needAccounts checks both test accounts have a token or a login.
func needAccounts(opts Options) error {
	var missing []string
	if opts.TokenA == "" && opts.LoginA == nil {
		missing = append(missing, EnvTokenA+" (account A)")
	}
	if opts.TokenB == "" && opts.LoginB == nil {
		missing = append(missing, EnvTokenB+" (account B)")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("set %s: the token of a test account seeded in the API "+
		"(the bare token: Procyon adds \"Bearer \" when the spec asks for it), "+
		"or declare how it logs in under test.accounts in .procyon.yaml", strings.Join(missing, " and "))
}

// authorize puts token into req the way cred says. The token is the bare
// value: Procyon adds the "Bearer " or "Basic " prefix the scheme needs.
func authorize(req *http.Request, cred *loader.Credential, token string) {
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

// mask hides every token in s, as written, URL-encoded and JSON-escaped (a
// JSON string escapes <, > and &, and PHP's escapes / too), so evidence
// never shows a credential, even one the API echoes back.
func mask(s string, tokens ...string) string {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		s = strings.ReplaceAll(s, token, "****")
		for _, escaped := range []string{url.QueryEscape(token), jsonEscaped(token), strings.ReplaceAll(token, "/", `\/`)} {
			if escaped != token {
				s = strings.ReplaceAll(s, escaped, "****")
			}
		}
	}
	return s
}

// jsonEscaped is token as encoding/json writes it inside a string.
func jsonEscaped(token string) string {
	quoted, _ := json.Marshal(token) // a string always marshals
	return string(quoted[1 : len(quoted)-1])
}
