package probe

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// maxGuessable is where an integer ID stops being small: a script tries
// every one below it, a million requests, in hours.
const maxGuessable = 1_000_000

// predictableID is the PRC107 finding of an operation the anonymous caller
// reached with f, or nil: when one of the IDs in its path or query is one
// anyone could guess (guessable), the ID is all that keeps a stranger from
// every other object it serves.
func (h *harvest) predictableID(op loader.Operation, f filled, exchange report.Exchange) *report.Finding {
	param, value, why, ok := h.guessable(f)
	if !ok {
		return nil
	}
	return &report.Finding{
		Rule:      lint.RuntimeRule("PRC107"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("A request with no credentials got %d with %s = %q, %s: anyone can try the next ones "+
			"and read every object this operation serves, with no account.", exchange.Status, param, value, why),
		Fix: "Give objects anyone can reach without an account IDs nobody can guess (a random UUID, or a random " +
			"token of 128 bits), or require authentication for the operation.",
		Evidence: []report.Exchange{exchange},
	}
}

// guessable returns the first ID f fills that anyone could guess, the
// parameter it fills and why: a small integer, or a value h's responses
// showed as the id of two kinds of object (a service and a car both "MQ",
// each the first row of its table, written in base64).
func (h *harvest) guessable(f filled) (param, value, why string, ok bool) {
	for i, v := range f.values {
		switch {
		case smallInteger(v):
			return f.params[i], v, "a small number", true
		case h.idOfTwoKinds(v):
			return f.params[i], v, "which is also the id of another kind of object, so it is counted, not random", true
		}
	}
	return "", "", "", false
}

// smallInteger reports whether v is a whole number below maxGuessable.
func smallInteger(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && n >= 0 && n < maxGuessable
}

// idOfTwoKinds reports whether h's responses showed value as the id of two
// objects of different kinds: neither has every field the other has. The
// same object read twice (in a list, then alone with more fields) is one
// kind; a service {id, name, price} and a car {id, plate, model} are two.
// Objects with the same fields are compared once, so a list of a thousand
// copies costs a thousand look-ups, not a million comparisons.
func (h *harvest) idOfTwoKinds(value string) bool {
	var kinds []object
	compared := map[string]bool{} // field names, joined, of the objects in kinds
	for _, path := range sortedKeys(h.byPath) {
		for _, o := range h.byPath[path] {
			if o["id"] != value {
				continue
			}
			fields := strings.Join(sortedKeys(o), " ")
			if compared[fields] {
				continue
			}
			if slices.ContainsFunc(kinds, func(k object) bool { return !hasFields(o, k) && !hasFields(k, o) }) {
				return true
			}
			compared[fields] = true
			kinds = append(kinds, o)
		}
	}
	return false
}

// hasFields reports whether o has every field other has.
func hasFields(o, other object) bool {
	for name := range other {
		if _, ok := o[name]; !ok {
			return false
		}
	}
	return true
}
