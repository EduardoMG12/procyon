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
// objects. When an item of B's answer is one of A's objects, it is a
// critical finding: the item holds a value that marks A (A's identity,
// which B's own reads never showed), and A's own answer to the same list
// showed that item too. This is where a value B saw in a list used only to
// skip the PRC102 test of an object (otherAccount) becomes a finding of its
// own.

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
// responses, and reports PRC108 when B's answer holds one of A's objects.
// aPath is the list as A reads it, to compare with. The cell is the
// finding when it leaks, otherwise what B's call got.
func (s *session) listLeak(ctx context.Context, op loader.Operation, aPath string) (report.Cell, error) {
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
	exchange, toB, err := s.sendFull(ctx, op, f.path, s.b)
	if err != nil || !success(exchange) {
		return cellOf(exchange, false), err
	}
	marked := s.markedAsA(itemsOf(toB))
	if len(marked) == 0 {
		return cellOf(exchange, false), nil
	}
	toA, err := s.answerToA(ctx, op, aPath)
	if err != nil {
		return report.Cell{}, err
	}
	found, ok := alsoIn(marked, itemsOf(toA))
	if !ok {
		return cellOf(exchange, false), nil
	}
	s.res.findings = append(s.res.findings, s.listLeakFinding(op, exchange, found))
	return cellOf(exchange, true), nil
}

// item is one item of a list answer: its "id" ("" when it has none), and
// every string and number it holds, at any depth.
type item struct {
	id     string
	values map[string]bool
}

// itemsOf is the items of a JSON list body, or none when it is not a list.
func itemsOf(body []byte) []item {
	v, _ := decode(body)
	list, _ := v.([]any)
	items := make([]item, 0, len(list))
	for _, element := range list {
		it := item{values: map[string]bool{}}
		fieldsIn(element, "", "", func(_, place, value string) {
			it.values[value] = true
			if normalize(place) == "id" { // the item's own id, not model.id
				it.id = value
			}
		})
		items = append(items, it)
	}
	return items
}

// mark is a value of A's found in an item of B's list, the item by its id.
type mark struct {
	itemID, value string
}

// markedAsA lists the marks of A in items: A's identity values (what A's
// reads showed and B's did not, such as A's username) that tell one account
// from another (telling: not "2", which a car model's id may also be) and
// are not also B's own. B's own list never holds them.
func (s *session) markedAsA(items []item) []mark {
	var marks []mark
	for _, it := range items {
		for _, value := range sortedKeys(s.ofA.identity) {
			if it.values[value] && telling(value) && s.ofB.identity[value] == "" {
				marks = append(marks, mark{it.id, value})
			}
		}
	}
	return marks
}

// alsoIn returns the first of marks whose item A's own list showed too:
// an item of A's with the same id that holds the same value. Without it,
// the item is B's own object holding A's value (an order B sent to A's
// phone number), not A's object.
func alsoIn(marks []mark, ofA []item) (mark, bool) {
	for _, m := range marks {
		for _, it := range ofA {
			if it.id == m.itemID && it.values[m.value] {
				return m, true
			}
		}
	}
	return mark{}, false
}

// listLeakFinding is a PRC108 finding: B's read of the list, which held
// A's object m.
func (s *session) listLeakFinding(op loader.Operation, exchange report.Exchange, m mark) report.Finding {
	which := "an item"
	if m.itemID != "" {
		which = fmt.Sprintf("the item with id %q", s.excerpt(m.itemID))
	}
	return report.Finding{
		Rule:      lint.RuntimeRule("PRC108"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("Test account B called this list as itself and got %d holding objects of test account A: "+
			"%s holds %q, which A's answer at %s showed and B's did not, and A's own list shows that item too. "+
			"The operation returns other users' objects, so any account can read them in bulk.",
			exchange.Status, which, s.excerpt(m.value), s.ofA.identity[m.value]),
		Fix: "On the server, scope the query to the caller (a list is read with `WHERE owner_id = ?`), and apply " +
			"any filter on top of that scope, never instead of it.",
		Evidence: []report.Exchange{exchange},
	}
}
