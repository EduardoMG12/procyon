package probe

import (
	"context"
	"net/http"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// discoverAccounts reads as A, then as B, and marks which values are each
// one's own (identityMarks). B reads only paths with nothing in them: what
// B is shown without naming an object, so a value B "saw" never comes from
// reading A's objects, which is the very thing being tested.
func (r *runner) discoverAccounts(ctx context.Context, ops []loader.Operation, a, b caller, ids map[string][]string) (ofA, ofB *discovery, err error) {
	if ofA, err = r.discover(ctx, ops, a, newHarvest(ids), false); err != nil {
		return nil, nil, err
	}
	if ofB, err = r.discover(ctx, ops, b, newHarvest(nil), true); err != nil {
		return nil, nil, err
	}
	ofA.identity, ofB.identity = identityMarks(ofA, ofB), identityMarks(ofB, ofA)
	return ofA, ofB, nil
}

// identityMarks lists the values that mark one account's own objects, by the
// path they came from: for each read both accounts made that answers one
// object (GET /me, not a list), the fields where the account's answer
// differs from the other's. A list is never used: a counter or a signed URL
// in every item would mark every item. A short value counts only in a field
// named like an identity (id, user, name, email, login): "17" as userId, but
// not "1" as a count.
func identityMarks(mine, theirs *discovery) map[string]string {
	marks := map[string]string{}
	for _, path := range sortedKeys(mine.byPath) {
		if !mine.single[path] || !theirs.single[path] {
			continue
		}
		// Objects in the same place of both answers ({"data": {...}} nests
		// the user one level down), compared field by field.
		for i := range min(len(mine.byPath[path]), len(theirs.byPath[path])) {
			own, other := mine.byPath[path][i], theirs.byPath[path][i]
			for _, field := range sortedKeys(own) {
				v := own[field]
				idLike := strings.HasSuffix(field, "id") || strings.Contains(field, "user") || strings.Contains(field, "name") ||
					strings.Contains(field, "email") || strings.Contains(field, "login")
				if v != other[field] && v != "" && v != "true" && v != "false" && (len(v) >= minTelling || idLike) {
					if _, seen := marks[v]; !seen {
						marks[v] = path
					}
				}
			}
		}
	}
	return marks
}

// discover calls who's reads (GET operations) and records what their
// responses show, so other operations' path parameters can be filled with
// who's objects. A read whose path needs a value waits until an earlier
// response has shown one, so it runs as soon as its parameters can be
// filled: GET /notes before GET /notes/{id}. Each pass calls every read
// that has become callable; it stops when a pass calls nothing new.
//
// It also returns what each read got, by operation, for the matrix.
//
// With topLevel, only reads with nothing in their path are called: what a
// caller sees without naming an object. B's discovery is that, so a value B
// "saw" never comes from reading A's objects, which is the very thing being
// tested.
func (r *runner) discover(ctx context.Context, ops []loader.Operation, who caller, h *harvest, topLevel bool) (*discovery, error) {
	d := &discovery{harvest: h, cells: map[string]report.Cell{}, bodies: map[string][]byte{}}
	done := make([]bool, len(ops))
	for progress := true; progress; {
		progress = false
		for i, op := range ops {
			if done[i] || op.Method != http.MethodGet || (topLevel && strings.Contains(op.Path, "{")) || r.skip[op.Key()] {
				continue
			}
			f, err := h.fill(op.Path)
			if err != nil {
				continue // not yet
			}
			path := f.path
			done[i], progress = true, true
			exchange, body, err := r.sendFull(ctx, op, path, who)
			if err != nil {
				return nil, err
			}
			key := op.Key()
			d.cells[key] = cellOf(exchange, false)
			if success(exchange) {
				h.add(op.Path, body)
				d.bodies[path] = body
			}
		}
	}
	return d, nil
}

// discovery is what one caller's reads showed.
type discovery struct {
	*harvest
	cells  map[string]report.Cell // what each read got, by operation, for the matrix
	bodies map[string][]byte      // each successful read's response body, by the path sent
}
