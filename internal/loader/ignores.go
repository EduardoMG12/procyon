package loader

import (
	"fmt"
	"maps"
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
// the element it is written on, and one on an operation that names a field
// covers only the findings about that field of its response.
const ignoreKey = "x-procyon-ignore"

// maxFieldDepth is how many names an ignore's field may join: far more than
// any answer nests.
const maxFieldDepth = 32

// parseIgnores reads every x-procyon-ignore in the spec. A malformed entry
// is an error: a typo must never silently ignore something. They are read
// in a stable order (what lives in a map, by key), so the notes about them
// and the error for a malformed one are the same on every run.
//
// An ignore on a security scheme also covers its OAuth2 flows. In a spec
// converted from Swagger 2.0, an ignore at the root also covers the servers
// (built from schemes and host, which cannot carry extensions).
func parseIgnores(doc *openapi3.T, asGiven func(report.Location) report.Location, swagger bool, known func(string) bool) ([]report.Ignore, error) {
	var ignores []report.Ignore
	var firstErr error
	// add parses the ignores written on one element.
	add := func(ext map[string]any, origin *openapi3.Origin, operation string, hasField func(string) bool, where string, about ...any) {
		if firstErr != nil {
			return
		}
		more, err := parseIgnoreList(ext[ignoreKey], operation, hasField, asGiven(LocateField(origin, ignoreKey)), known)
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
	addServers := func(servers openapi3.Servers) {
		for _, server := range servers {
			add(server.Extensions, server.Origin, "", nil, "server "+server.URL, server)
		}
	}
	add(doc.Extensions, doc.Origin, "", nil, "the spec", root...)
	addServers(doc.Servers)
	if doc.Paths != nil {
		paths := doc.Paths.Map()
		for _, path := range slices.Sorted(maps.Keys(paths)) {
			addServers(paths[path].Servers)
		}
	}
	ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		add(op.Extensions, op.Origin, OperationKey(method, path), func(field string) bool { return inResponse(op, field) }, "")
		if op.Servers != nil {
			addServers(*op.Servers)
		}
	})
	ForEachScheme(doc, func(name string, scheme *openapi3.SecurityScheme) {
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
		add(scheme.Extensions, scheme.Origin, "", nil, "security scheme "+name, covered...)
		names := []string{"implicit", "password", "clientCredentials", "authorizationCode"}
		for i, flow := range flows {
			if flow != nil {
				add(flow.Extensions, flow.Origin, "", nil, "the "+names[i]+" flow of "+name, flow)
			}
		}
	})
	return ignores, firstErr
}

func parseIgnoreList(value any, operation string, hasField func(string) bool, loc report.Location, known func(string) bool) ([]report.Ignore, error) {
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
		return nil, fail("must be a list of {rule, reason, expires, field}")
	}
	var ignores []report.Ignore
	for i, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			return nil, fail("entry %d must be an object with rule and reason", i+1)
		}
		for key := range fields {
			if !slices.Contains([]string{"rule", "reason", "expires", "field"}, key) {
				return nil, fail("entry %d has an unknown key %q (use rule, reason, expires, field)", i+1, key)
			}
		}
		ig := report.Ignore{Operation: operation, Location: loc}
		ig.Rule, _ = fields["rule"].(string)
		if known == nil || !known(ig.Rule) {
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
		if raw, set := fields["field"]; set {
			ig.Field, _ = raw.(string)
			switch {
			case hasField == nil:
				return nil, fail("entry %d (%s): field names a field of an operation's response, so it is only for an ignore on an operation", i+1, ig.Rule)
			case ig.Field == "" || !hasField(ig.Field):
				return nil, fail("entry %d (%s): field %q is no field of the operation's response schema "+
					"(a nested field is written reviews.email)", i+1, ig.Rule, fmt.Sprint(raw))
			}
		}
		ignores = append(ignores, ig)
	}
	return ignores, nil
}

// inResponse reports whether a response schema of op has the field at
// path: property names joined by dots, lists left out, so "reviews.email"
// is the email of every review in {"reviews": [{"email": ...}]}. An ignore
// may only name a field the spec describes: a typo must stop the run, and
// the field it excuses is then written down for reviewers.
//
// Each name walks every schema the level before can reach, so a hostile
// spec's "a.a.a…" over a recursive schema could cost names × schemas; a
// path deeper than maxFieldDepth names no field.
func inResponse(op *openapi3.Operation, path string) bool {
	if strings.Count(path, ".") >= maxFieldDepth {
		return false
	}
	var level []*openapi3.SchemaRef
	if op.Responses != nil {
		for _, response := range op.Responses.Map() {
			if response == nil || response.Value == nil {
				continue
			}
			for _, media := range response.Value.Content {
				if media != nil {
					level = append(level, media.Schema)
				}
			}
		}
	}
	for _, name := range strings.Split(path, ".") {
		var next []*openapi3.SchemaRef
		for _, s := range holders(level) {
			if prop := s.Properties[name]; prop != nil {
				next = append(next, prop)
			}
		}
		if len(next) == 0 {
			return false
		}
		level = next
	}
	return true
}

// holders lists the schemas whose properties a value of one of refs can
// have: each schema, its list items, and its allOf, oneOf and anyOf parts,
// at any depth. Each schema is listed once, so a recursive one ends.
func holders(refs []*openapi3.SchemaRef) []*openapi3.Schema {
	var found []*openapi3.Schema
	seen := map[*openapi3.Schema]bool{}
	for len(refs) > 0 {
		ref := refs[0]
		refs = refs[1:]
		if ref == nil || ref.Value == nil || seen[ref.Value] {
			continue
		}
		s := ref.Value
		seen[s] = true
		found = append(found, s)
		refs = append(refs, s.Items)
		refs = append(refs, s.AllOf...)
		refs = append(refs, s.OneOf...)
		refs = append(refs, s.AnyOf...)
	}
	return found
}
