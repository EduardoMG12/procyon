package probe

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// discoverAccounts has each account create its own objects (create), then
// reads as A, then as B, and marks which values are each one's own
// (identityMarks). B reads only paths with nothing in them: what B is shown
// without naming an object, so a value B "saw" never comes from reading A's
// objects, which is the very thing being tested. created lists what each
// account made, for a note.
func (r *runner) discoverAccounts(ctx context.Context, ops []loader.Operation, a, b caller, ids map[string][]string) (ofA, ofB *discovery, created []string, err error) {
	madeA, err := r.create(ctx, ops, a)
	if err != nil {
		return nil, nil, nil, err
	}
	madeB, err := r.create(ctx, ops, b)
	if err != nil {
		return nil, nil, nil, err
	}
	if ofA, err = r.discover(ctx, ops, a, newHarvest(ids), false); err != nil {
		return nil, nil, nil, err
	}
	if ofB, err = r.discover(ctx, ops, b, newHarvest(nil), true); err != nil {
		return nil, nil, nil, err
	}
	// What an account created is recorded after what it read, so an object
	// the environment seeded comes first: it holds real data, where a
	// created one holds only the example both accounts sent.
	for _, account := range []struct {
		name string
		d    *discovery
		made []createdObject
	}{{a.name, ofA, madeA}, {b.name, ofB, madeB}} {
		for _, m := range account.made {
			account.d.add(m.path, m.body)
			created = append(created, account.name+": POST "+m.path)
		}
	}
	ofA.identity, ofB.identity = identityMarks(ofA, ofB), identityMarks(ofB, ofA)
	return ofA, ofB, created, nil
}

// create has who add one object to every collection the spec lets it add
// to, so it has an object of its own to be tested with even when the
// environment seeded none: a POST on a collection, a path that also has a
// GET or a GET on one of its items (POST /notes next to GET /notes or GET
// /notes/{id}), with the spec's example as the body. What it answers is
// recorded like a read, under the collection's path, so the new object's
// ID can fill /notes/{id} when nothing else can. Only collections: a POST /logout or
// /reset-password has neither, and is never sent.
func (r *runner) create(ctx context.Context, ops []loader.Operation, who caller) (made []createdObject, err error) {
	for _, op := range ops {
		if op.Method != http.MethodPost || strings.Contains(op.Path, "{") || op.Public || op.Body == nil || r.skip[op.Key()] ||
			!isCollection(ops, op.Path) {
			continue
		}
		exchange, body, err := r.sendFull(ctx, op, op.Path, who)
		if err != nil {
			return nil, err
		}
		if success(exchange) {
			made = append(made, createdObject{op.Path, body})
		}
	}
	return made, nil
}

// createdObject is what an account's POST to a collection answered.
type createdObject struct {
	path string
	body []byte
}

// isCollection reports whether path holds objects: a GET on it, or on one
// of its items ({id} right below it).
func isCollection(ops []loader.Operation, path string) bool {
	return slices.ContainsFunc(ops, func(o loader.Operation) bool {
		if o.Method != http.MethodGet {
			return false
		}
		item, ok := strings.CutPrefix(o.Path, path+"/{")
		return o.Path == path || ok && strings.Count(item, "/") == 0
	})
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
// With topLevel, only reads with nothing in their path and no required
// query are called: what a caller sees without naming an object. B's
// discovery is that, so a value B "saw" never comes from reading A's
// objects, which is the very thing being tested.
func (r *runner) discover(ctx context.Context, ops []loader.Operation, who caller, h *harvest, topLevel bool) (*discovery, error) {
	d := &discovery{harvest: h, cells: map[string]report.Cell{}, bodies: map[string][]byte{}}
	done := make([]bool, len(ops))
	for progress := true; progress; {
		progress = false
		for i, op := range ops {
			if done[i] || op.Method != http.MethodGet || (topLevel && (strings.Contains(op.Path, "{") || len(op.Query) > 0)) || r.skip[op.Key()] {
				continue
			}
			f, err := h.fill(op.Path, op.Query)
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
