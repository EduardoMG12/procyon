package probe

import (
	"fmt"
	"net/http"
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
