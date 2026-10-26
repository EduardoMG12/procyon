package lint

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// ignoreKey holds ignores. Written on an operation, it covers that
// operation's findings; on a security scheme, a server or an OAuth2 flow,
// that element's findings; at the spec's root, findings about the spec as a
// whole (its default security requirement). An ignore never reaches beyond
// the element it is written on.
const ignoreKey = "x-procyon-ignore"

// parseIgnores reads every x-procyon-ignore in the spec. A malformed entry
// is an error: a typo must never silently ignore something.
//
// An ignore on a security scheme also covers its OAuth2 flows. In a spec
// converted from Swagger 2.0, an ignore at the root also covers the servers
// (built from schemes and host, which cannot carry extensions).
func parseIgnores(doc *openapi3.T, asGiven func(report.Location) report.Location, swagger bool) ([]report.Ignore, error) {
	var ignores []report.Ignore
	var firstErr error
	// add parses the ignores written on one element.
	add := func(ext map[string]any, origin *openapi3.Origin, operation string, where string, about ...any) {
		if firstErr != nil {
			return
		}
		more, err := parseIgnoreList(ext[ignoreKey], operation, asGiven(locateField(origin, ignoreKey)))
		for i := range more {
			more[i].Elements, more[i].Where = about, where
		}
		ignores, firstErr = append(ignores, more...), err
	}
	root := []any{doc}
	if swagger {
		for _, server := range doc.Servers {
			root = append(root, server)
		}
	}
	add(doc.Extensions, doc.Origin, "", "the spec", root...)
	for _, server := range doc.Servers {
		add(server.Extensions, server.Origin, "", "server "+server.URL, server)
	}
	if doc.Paths != nil {
		for _, item := range doc.Paths.Map() {
			for _, server := range item.Servers {
				add(server.Extensions, server.Origin, "", "server "+server.URL, server)
			}
		}
	}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		add(op.Extensions, op.Origin, method+" "+path, "")
		if op.Servers != nil {
			for _, server := range *op.Servers {
				add(server.Extensions, server.Origin, "", "server "+server.URL, server)
			}
		}
	})
	forEachScheme(doc, func(name string, scheme *openapi3.SecurityScheme) {
		covered := []any{scheme}
		var flows []*openapi3.OAuthFlow
		if f := scheme.Flows; f != nil {
			flows = []*openapi3.OAuthFlow{f.Implicit, f.Password, f.ClientCredentials, f.AuthorizationCode}
		}
		for _, flow := range flows {
			if flow != nil {
				covered = append(covered, flow)
			}
		}
		add(scheme.Extensions, scheme.Origin, "", "security scheme "+name, covered...)
		names := []string{"implicit", "password", "clientCredentials", "authorizationCode"}
		for i, flow := range flows {
			if flow != nil {
				add(flow.Extensions, flow.Origin, "", "the "+names[i]+" flow of "+name, flow)
			}
		}
	})
	return ignores, firstErr
}

func parseIgnoreList(value any, operation string, loc report.Location) ([]report.Ignore, error) {
	// Errors name the operation when there is one; otherwise the location
	// says where.
	if value == nil {
		return nil, nil
	}
	fail := func(format string, args ...any) error {
		where := ""
		if operation != "" {
			where = operation + ": "
		}
		return fmt.Errorf("%s:%d:%d: %s%s: %s", loc.File, loc.Line, loc.Column, where, ignoreKey, fmt.Sprintf(format, args...))
	}
	entries, ok := value.([]any)
	if !ok {
		return nil, fail("must be a list of {rule, reason, expires}")
	}
	var ignores []report.Ignore
	for i, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			return nil, fail("entry %d must be an object with rule and reason", i+1)
		}
		for key := range fields {
			if !slices.Contains([]string{"rule", "reason", "expires"}, key) {
				return nil, fail("entry %d has an unknown key %q (use rule, reason, expires)", i+1, key)
			}
		}
		ig := report.Ignore{Operation: operation, Location: loc}
		ig.Rule, _ = fields["rule"].(string)
		if !knownRule(ig.Rule) {
			return nil, fail("entry %d: unknown rule %q", i+1, ig.Rule)
		}
		ig.Reason, _ = fields["reason"].(string)
		if ig.Reason = strings.TrimSpace(ig.Reason); ig.Reason == "" {
			return nil, fail("entry %d (%s) needs a reason: why is this finding acceptable here?", i+1, ig.Rule)
		}
		if raw, set := fields["expires"]; set {
			ig.Expires = fmt.Sprint(raw)
			until, err := time.Parse(time.DateOnly, ig.Expires)
			if err != nil {
				return nil, fail("entry %d (%s): expires %q is not a date like 2027-01-31", i+1, ig.Rule, ig.Expires)
			}
			ig.Until = until
		}
		ignores = append(ignores, ig)
	}
	return ignores, nil
}

func knownRule(id string) bool {
	isID := func(r report.Rule) bool { return r.ID == id }
	return slices.ContainsFunc(Rules(), isID) || slices.ContainsFunc(runtimeRules, isID)
}
