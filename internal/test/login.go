package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
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
type Login struct {
	Operation string `yaml:"operation"` // "POST /login", as in the spec
	Body      any    `yaml:"body"`      // sent as JSON; ${VAR} in strings reads the environment
	Token     string `yaml:"token"`     // JSON pointer to the token in the response
}

// login signs who in and returns its token. It goes through the same
// client as every other request, so it is subject to the same target
// checks, timeout and budget.
func (r *runner) login(ctx context.Context, spec *lint.Spec, who string, l *Login) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("login of test account %s: %s", who, fmt.Sprintf(format, args...))
	}
	var op *lint.Operation
	for _, o := range spec.Operations() {
		if o.Method+" "+o.Path == l.Operation {
			op = &o
			break
		}
	}
	if op == nil {
		return fail("the spec has no operation %q", l.Operation)
	}
	body, err := json.Marshal(expand(l.Body))
	if err != nil {
		return fail("body: %v", err)
	}
	signIn := *op
	signIn.Body, signIn.Credential = body, nil
	exchange, got, err := r.sendFull(ctx, signIn, op.Path, anonymous)
	if err != nil {
		return "", err
	}
	if !success(exchange) {
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

// expand replaces ${VAR} in every string of a decoded YAML value with the
// environment variable, so the config never needs a literal password.
func expand(v any) any {
	switch v := v.(type) {
	case string:
		return os.Expand(v, os.Getenv)
	case map[string]any:
		out := map[string]any{}
		for k, field := range v {
			out[k] = expand(field)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = expand(item)
		}
		return out
	}
	return v
}

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
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
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
