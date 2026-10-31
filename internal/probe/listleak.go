package probe

import (
	"context"
	"fmt"
	"net/http"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// PRC108: another account's list shows A's objects. For every list and
// search operation A read, B reads it too, with a required filter given B's
// own value, never A's: a search that ignores its filter returns everyone's
// objects. When B's answer holds a value that marks one of A's objects
// (A's identity, which B's own reads never showed), it is a critical
// finding. This is where a value B saw in a list used only to skip the
// PRC102 test of an object (otherAccount) becomes a finding of its own.

// isList reports whether op is a list or search that A read: a GET, not in
// test.skip, whose 2xx answer to A was a JSON array, not one object.
func (s *session) isList(op loader.Operation) bool {
	if op.Method != http.MethodGet || s.skip[op.Key()] {
		return false
	}
	single, answered := s.ofA.single[op.Path]
	return answered && !single && s.ofA.cells[op.Key()].Outcome == report.Allowed
}

// listLeak reads op as B, with its required filter filled from B's own
// responses, and reports PRC108 when B's answer holds A's objects. The cell
// is the finding when it leaks, otherwise what B's call got.
func (s *session) listLeak(ctx context.Context, op loader.Operation) (report.Cell, error) {
	for _, q := range op.Query {
		if _, _, ok := s.ofB.pick(op.Path, q.Name); !ok {
			s.res.noteOn(op, fmt.Sprintf("not tested for PRC108: B has no value of its own for the required filter %q", q.Name))
			return skipped, nil
		}
	}
	f, err := s.ofB.fill(op.Path, op.Query)
	if err != nil {
		s.res.noteOn(op, fmt.Sprintf("not tested for PRC108: %v in B's responses", err))
		return skipped, nil
	}
	exchange, body, err := s.sendFull(ctx, op, f.path, s.b)
	if err != nil || !success(exchange) {
		return cellOf(exchange, false), err
	}
	leaked := s.aObjectsIn(body)
	if len(leaked) == 0 {
		return cellOf(exchange, false), nil
	}
	s.res.findings = append(s.res.findings, listLeakFinding(op, exchange))
	return cellOf(exchange, true), nil
}

// aObjectsIn lists the values in a response that mark A's objects: A's
// identity values (what A's reads showed and B's did not, such as A's
// username) that are not also B's own. B's own list never holds them, so
// one of them in B's answer is A's object shown to B.
func (s *session) aObjectsIn(body []byte) []string {
	inBody := setOf(valuesIn(body))
	var leaked []string
	for _, value := range sortedKeys(s.ofA.identity) {
		if inBody[value] && s.ofB.identity[value] == "" {
			leaked = append(leaked, value)
		}
	}
	return leaked
}

// listLeakFinding is a PRC108 finding: B's read of the list, which held A's
// objects.
func listLeakFinding(op loader.Operation, exchange report.Exchange) report.Finding {
	return report.Finding{
		Rule:      lint.RuntimeRule("PRC108"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("Test account B called this list as itself and got %d holding objects of test account A: "+
			"the operation returns other users' objects, so any account can read them in bulk.", exchange.Status),
		Fix: "On the server, scope the query to the caller (a list is read with `WHERE owner_id = ?`), and apply " +
			"any filter on top of that scope, never instead of it.",
		Evidence: []report.Exchange{exchange},
	}
}
