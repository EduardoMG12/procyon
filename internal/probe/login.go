package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
)

// Login is how a test account signs in, declared in .procyon.yaml:
//
//	test:
//	  accounts:
//	    a:
//	      login:
//	        operation: POST /login
//	        body: {username: alice, password: "${PROCYON_A_PASSWORD}"}
//	        token: /session/token
//
// form replaces body for a login that takes a form (FastAPI's OAuth2
// password flow), and cookie replaces token when the answer sets the token
// as a cookie instead of returning it.
type Login struct {
	Operation string            `yaml:"operation"` // "POST /login", as in the spec
	Body      any               `yaml:"body"`      // sent as JSON; ${VAR} in strings reads the environment
	Form      map[string]string `yaml:"form"`      // or sent form-encoded; ${VAR} too
	Token     string            `yaml:"token"`     // JSON pointer to the token in the response
	Cookie    string            `yaml:"cookie"`    // or the name of the cookie the response sets
}

// signIn returns the two test accounts with their tokens: from the
// environment, which wins, or from their declared login.
func (r *runner) signIn(ctx context.Context, spec *loader.Spec, opts Options) (a, b caller, err error) {
	a = caller{name: "A", token: opts.TokenA}
	b = caller{name: "B", token: opts.TokenB}
	for _, account := range []struct {
		who   *caller
		login *Login
	}{{&a, opts.LoginA}, {&b, opts.LoginB}} {
		if account.who.token == "" {
			if account.who.token, err = r.login(ctx, spec, account.who.name, account.login); err != nil {
				return a, b, err
			}
		}
		r.tokens = append(r.tokens, account.who.token)
	}
	return a, b, nil
}

// login signs who in and returns its token. It goes through the same
// client as every other request, so it is subject to the same target
// checks, timeout and budget.
func (r *runner) login(ctx context.Context, spec *loader.Spec, who string, l *Login) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("login of test account %s: %s", who, fmt.Sprintf(format, args...))
	}
	method, path, _ := strings.Cut(strings.TrimSpace(l.Operation), " ")
	method = strings.ToUpper(method)
	var op *loader.Operation
	for _, o := range spec.Operations() {
		if o.Method == method && o.Path == strings.TrimSpace(path) {
			op = &o
			break
		}
	}
	switch {
	case op == nil:
		return fail("the spec has no operation %q", l.Operation)
	case strings.Contains(op.Path, "{"):
		return fail("%s needs a value in its path; use a login operation without one", l.Operation)
	case op.Method == http.MethodGet && (l.Body != nil || l.Form != nil):
		return fail("%s is a GET, which sends no body", l.Operation)
	}
	body, contentType, err := r.loginBody(l)
	if err != nil {
		return "", fmt.Errorf("login of test account %s: %w", who, err)
	}
	signIn := *op
	signIn.Body, signIn.Credential = body, nil
	exchange, got, resp, err := r.sendWith(ctx, signIn, op.Path, anonymous, contentType)
	if err != nil {
		return "", fmt.Errorf("login of test account %s: %w", who, err)
	}
	redirect := exchange.Status >= 300 && exchange.Status < 400
	// A login that sets a cookie often redirects to the app's start page;
	// the cookie comes with the redirect.
	if l.Cookie != "" && (success(exchange) || redirect) {
		for _, c := range resp.Cookies() {
			if c.Name == l.Cookie && c.Value != "" {
				return c.Value, nil
			}
		}
		return fail("%s answered %d with no cookie %s", l.Operation, exchange.Status, l.Cookie)
	}
	if !success(exchange) {
		if redirect {
			return fail("%s answered %d: redirects are not followed, and the token must be in the JSON answer", l.Operation, exchange.Status)
		}
		return fail("%s answered %d", l.Operation, exchange.Status)
	}
	v, ok := decode(got)
	if !ok {
		return fail("the response is not JSON")
	}
	token, ok := pointer(v, l.Token).(string)
	if !ok || token == "" {
		return fail("no string at %s in the response", l.Token)
	}
	return token, nil
}

// loginBody is what a login sends, and its media type: its form,
// form-encoded, or else its body as JSON. ${PROCYON_...} values are read
// from the environment and masked like tokens, in case the API echoes them.
func (r *runner) loginBody(l *Login) (body []byte, contentType string, err error) {
	fields := l.Body
	if l.Form != nil {
		form := map[string]any{}
		for name, value := range l.Form {
			form[name] = value
		}
		fields = form
	}
	expanded, secrets, err := expand(fields)
	if err != nil {
		return nil, "", err
	}
	r.tokens = append(r.tokens, secrets...)
	if l.Form != nil {
		values := url.Values{}
		for name, value := range expanded.(map[string]any) {
			values.Set(name, value.(string))
		}
		return []byte(values.Encode()), "application/x-www-form-urlencoded", nil
	}
	if body, err = json.Marshal(expanded); err != nil {
		return nil, "", fmt.Errorf("body: %w", err)
	}
	return body, "application/json", nil
}

// envVar is ${NAME}, the only form expand replaces: a bare $ in a literal
// password stays as written.
var envVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expand replaces ${NAME} in every string of a decoded YAML value with the
// environment variable, so the config never needs a literal password. It
// returns the values it read, to mask them, and fails on an unset one
// (naming it, never a value).
func expand(v any) (any, []string, error) {
	var secrets []string
	var missing, refused string
	var expandValue func(any) any
	expandValue = func(v any) any {
		switch v := v.(type) {
		case string:
			return envVar.ReplaceAllStringFunc(v, func(m string) string {
				name := envVar.FindStringSubmatch(m)[1]
				if !strings.HasPrefix(name, "PROCYON_") {
					if refused == "" {
						refused = name
					}
					return ""
				}
				value, ok := os.LookupEnv(name)
				if !ok && missing == "" {
					missing = name
				}
				if value != "" {
					secrets = append(secrets, value)
				}
				return value
			})
		case map[string]any:
			out := map[string]any{}
			for k, field := range v {
				out[k] = expandValue(field)
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				out[i] = expandValue(item)
			}
			return out
		}
		return v
	}
	out := expandValue(v)
	if refused != "" {
		// The config sits next to the spec, where a pull request can change
		// it: it must not be able to send CI's other secrets to the target.
		return nil, nil, fmt.Errorf("${%s}: only variables named PROCYON_* can be used in a login", refused)
	}
	if missing != "" {
		return nil, nil, fmt.Errorf("${%s} is not set", missing)
	}
	return out, secrets, nil
}

// pointerEscapes undoes a JSON pointer's escapes: ~1 is a / and ~0 a ~.
var pointerEscapes = strings.NewReplacer("~1", "/", "~0", "~")

// pointer resolves a JSON pointer (RFC 6901: /session/token, /items/0/id)
// in a decoded JSON value, or returns nil.
func pointer(v any, ptr string) any {
	if ptr == "" {
		return v
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil
	}
	for _, part := range strings.Split(ptr[1:], "/") {
		part = pointerEscapes.Replace(part)
		switch node := v.(type) {
		case map[string]any:
			v = node[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
	}
	return v
}
