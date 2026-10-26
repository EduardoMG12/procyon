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

// ignore is one parsed x-procyon-ignore entry.
type ignore struct {
	rule      string
	reason    string
	expires   string    // as written
	until     time.Time // the expiry date (its day, month and year only)
	operation string    // the operation it is written on, or ""
	about     []any     // the elements it covers, when not an operation
	where     string    // how notes name that element
	location  report.Location
	used      bool
}

// on names where the ignore lives, for notes.
func (ig *ignore) on() string {
	if ig.operation != "" {
		return ig.operation
	}
	return ig.where
}

// covers reports whether the ignore is written on the element f is about.
func (ig *ignore) covers(f report.Finding) bool {
	if ig.rule != f.Rule.ID {
		return false
	}
	if ig.operation != "" {
		return ig.operation == f.Operation
	}
	return f.Element != nil && slices.Contains(ig.about, f.Element)
}

// parseIgnores reads every x-procyon-ignore in the spec. A malformed entry
// is an error: a typo must never silently ignore something.
//
// An ignore on a security scheme also covers its OAuth2 flows. In a spec
// converted from Swagger 2.0, an ignore at the root also covers the servers
// (built from schemes and host, which cannot carry extensions).
func parseIgnores(doc *openapi3.T, asGiven func(report.Location) report.Location, swagger bool) ([]*ignore, error) {
	var ignores []*ignore
	var firstErr error
	// add parses the ignores written on one element.
	add := func(ext map[string]any, origin *openapi3.Origin, operation string, where string, about ...any) {
		if firstErr != nil {
			return
		}
		more, err := parseIgnoreList(ext[ignoreKey], operation, asGiven(locateField(origin, ignoreKey)))
		for _, ig := range more {
			ig.about, ig.where = about, where
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

func parseIgnoreList(value any, operation string, loc report.Location) ([]*ignore, error) {
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
	var ignores []*ignore
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
		ig := &ignore{operation: operation, location: loc}
		ig.rule, _ = fields["rule"].(string)
		if !knownRule(ig.rule) {
			return nil, fail("entry %d: unknown rule %q", i+1, ig.rule)
		}
		ig.reason, _ = fields["reason"].(string)
		if ig.reason = strings.TrimSpace(ig.reason); ig.reason == "" {
			return nil, fail("entry %d (%s) needs a reason: why is this finding acceptable here?", i+1, ig.rule)
		}
		if raw, set := fields["expires"]; set {
			ig.expires = fmt.Sprint(raw)
			until, err := time.Parse(time.DateOnly, ig.expires)
			if err != nil {
				return nil, fail("entry %d (%s): expires %q is not a date like 2027-01-31", i+1, ig.rule, ig.expires)
			}
			ig.until = until
		}
		ignores = append(ignores, ig)
	}
	return ignores, nil
}

func knownRule(id string) bool {
	isID := func(r report.Rule) bool { return r.ID == id }
	return slices.ContainsFunc(Rules(), isID) || slices.ContainsFunc(runtimeRules, isID)
}

// applyIgnores moves the findings an ignore matches out of report.Findings
// into report.Ignored, and adds notes for expired and unused ignores. An
// ignore expires at the end of its date.
func applyIgnores(rep *report.Report, ignores []*ignore, today time.Time) {
	// An ignore lasts until the end of its date where Procyon runs, so the
	// same spec gives the same verdict all day in any time zone.
	expired := func(ig *ignore) bool {
		if ig.until.IsZero() {
			return false
		}
		y, m, d := ig.until.Date()
		return !today.Before(time.Date(y, m, d+1, 0, 0, 0, 0, today.Location()))
	}
	kept := rep.Findings[:0]
	for _, f := range rep.Findings {
		// A finding about a shared schema is checked operation by
		// operation: an ignore on one covers that one only, and the finding
		// is gone only when every operation is ignored.
		var left []string
		for _, op := range append([]string{f.Operation}, f.Also...) {
			one := f
			one.Operation, one.Also = op, nil
			i := slices.IndexFunc(ignores, func(ig *ignore) bool { return ig.covers(one) && !expired(ig) })
			if i < 0 {
				left = append(left, op)
				continue
			}
			ignores[i].used = true
			rep.Ignored = append(rep.Ignored, report.IgnoredFinding{Finding: one, Reason: ignores[i].reason, Expires: ignores[i].expires})
		}
		if len(left) > 0 {
			f.Operation, f.Also = left[0], left[1:]
			kept = append(kept, f)
		}
	}
	rep.Findings = kept
	for _, ig := range ignores {
		switch {
		case expired(ig):
			rep.Notes = append(rep.Notes, report.Note{Location: ig.location, Message: fmt.Sprintf("ignore of %s on %s expired on %s; its findings count again", ig.rule, ig.on(), ig.expires)})
		case !ig.used:
			rep.Notes = append(rep.Notes, report.Note{Location: ig.location, Message: fmt.Sprintf("ignore of %s on %s matches no finding; remove it", ig.rule, ig.on())})
		}
	}
}
