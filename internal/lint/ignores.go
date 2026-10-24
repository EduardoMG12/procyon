package lint

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

// ignoreKey holds ignores: on an operation, for findings about that
// operation; at the spec's root, for findings about no operation (a
// security scheme, a server, an OAuth2 flow).
const ignoreKey = "x-procyon-ignore"

// IgnoredFinding is a finding an ignore matched. It is still reported, and
// never fails the run.
type IgnoredFinding struct {
	Finding Finding
	Reason  string
	Expires string // "2027-01-31", or "" for never
}

// Note is something a run wants the reader to know that is not a finding: an
// ignore that expired, or one that matches nothing. Notes never fail a run.
type Note struct {
	Location Location
	Message  string
}

// ignore is one parsed x-procyon-ignore entry.
type ignore struct {
	rule      string
	reason    string
	expires   string    // as written
	until     time.Time // zero when it never expires
	operation string    // "" at the spec's root
	location  Location
	used      bool
}

// on names where the ignore lives, for notes.
func (ig *ignore) on() string {
	if ig.operation == "" {
		return "the spec"
	}
	return ig.operation
}

// parseIgnores reads every x-procyon-ignore in the spec. A malformed entry
// is an error: a typo must never silently ignore something.
func parseIgnores(doc *openapi3.T, asGiven func(Location) Location) ([]*ignore, error) {
	ignores, err := parseIgnoreList(doc.Extensions[ignoreKey], "", asGiven(locateField(doc.Origin, ignoreKey)))
	if err != nil {
		return nil, err
	}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if err != nil {
			return
		}
		var more []*ignore
		more, err = parseIgnoreList(op.Extensions[ignoreKey], method+" "+path, asGiven(locateField(op.Origin, ignoreKey)))
		ignores = append(ignores, more...)
	})
	return ignores, err
}

func parseIgnoreList(value any, operation string, loc Location) ([]*ignore, error) {
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
	return slices.ContainsFunc(rules, func(r Rule) bool { return r.ID == id })
}

// applyIgnores moves the findings an ignore matches out of report.Findings
// into report.Ignored, and adds notes for expired and unused ignores. An
// ignore expires at the end of its date.
func applyIgnores(report *Report, ignores []*ignore, today time.Time) {
	expired := func(ig *ignore) bool {
		return !ig.until.IsZero() && today.After(ig.until.AddDate(0, 0, 1).Add(-time.Nanosecond))
	}
	kept := report.Findings[:0]
	for _, f := range report.Findings {
		i := slices.IndexFunc(ignores, func(ig *ignore) bool {
			return ig.rule == f.Rule.ID && ig.operation == f.Operation && !expired(ig)
		})
		if i < 0 {
			kept = append(kept, f)
			continue
		}
		ignores[i].used = true
		report.Ignored = append(report.Ignored, IgnoredFinding{Finding: f, Reason: ignores[i].reason, Expires: ignores[i].expires})
	}
	report.Findings = kept
	for _, ig := range ignores {
		switch {
		case expired(ig):
			report.Notes = append(report.Notes, Note{ig.location,
				fmt.Sprintf("ignore of %s on %s expired on %s; its findings count again", ig.rule, ig.on(), ig.expires)})
		case !ig.used:
			report.Notes = append(report.Notes, Note{ig.location,
				fmt.Sprintf("ignore of %s on %s matches no finding; remove it", ig.rule, ig.on())})
		}
	}
}
