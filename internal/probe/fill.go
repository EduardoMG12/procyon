package probe

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/words"
)

// How an account's harvest gives an operation's parameters values, so the
// account can call it on its own objects (or on another account's).

// pick returns a value for parameter param of path, and whether it is
// known to be the account's own. In order:
//
//  1. for a path parameter, the parent collection's objects' field of the
//     same name, then their "id": GET /notes fills /notes/{id} and
//     /notes/{noteId};
//  2. a field of the same name in any path's objects, paths by name;
//  3. a value declared in .procyon.yaml, which is the account's own.
//
// Among the objects of 1 or 2, one that holds an identity value from
// another path (a book whose "user" is the username GET /me showed) wins:
// it is the account's own. Otherwise the first one is taken, not known to
// be own, and a declared value, when there is one, is preferred to it.
func (h *harvest) pick(path, param string) (value string, own, ok bool) {
	key := normalize(param)
	if parent, inPath := parentOf(path, param); inPath {
		value, own, ok = h.choose(parent, key, "id")
	}
	for _, p := range sortedKeys(h.byPath) {
		if ok {
			break
		}
		value, own, ok = h.choose(p, key)
	}
	if declared := h.declared[key]; len(declared) > 0 && !own {
		return declared[0], true, true
	}
	return value, own, ok
}

// parentOf is the collection above parameter param of path: /notes for
// {id} in /notes/{id}. A query parameter is not in the path, and has none.
func parentOf(path, param string) (parent string, inPath bool) {
	parent, _, inPath = strings.Cut(path, "/{"+param+"}")
	return parent, inPath
}

// choose is pick's choice among the objects seen at path from: the value
// of the first of fields that any of them holds (an empty value is none),
// taken from the account's own object (ownObject) when one has it, else
// from the first object that has it.
func (h *harvest) choose(from string, fields ...string) (value string, own, ok bool) {
	for _, field := range fields {
		first := ""
		for _, o := range h.byPath[from] {
			v, has := o[field]
			if !has {
				continue
			}
			if h.ownObject(o, from) {
				return v, true, true
			}
			if first == "" {
				first = v
			}
		}
		if first != "" {
			return first, false, true
		}
	}
	return "", false, false
}

// ownObject reports whether o, seen at path from, holds an identity value
// that came from another path: a book whose "user" is the username GET /me
// showed is the account's own.
func (h *harvest) ownObject(o object, from string) bool {
	for _, value := range o {
		if source, mark := h.identity[value]; mark && source != from {
			return true
		}
	}
	return false
}

// namesObject reports whether a parameter's name says it names one object:
// its last word is id or uuid (picture_id, reportId, orderUUID). A
// filter (status, sort, page) names none.
func namesObject(name string) bool {
	parts := words.Split(name)
	return len(parts) > 0 && words.OneOf(parts[len(parts)-1], []string{"id", "uuid"})
}

// pathParam matches a path parameter: {id}, {orderId}.
var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// filled is a path with every parameter given a value.
type filled struct {
	path string // escaped, ready to send: /notes/1, or /notes?owner=alice
	// values are the values used that name an object, unescaped: not a
	// query parameter's example, which names none of the account's.
	values []string
	params []string // the parameter each of values fills, in the same order
	own    bool     // every value is known to be the account's own
	// examples are the required query parameters filled with the spec's
	// example, and unfilled the optional ones that name an object but got
	// no value, for notes.
	examples, unfilled []string
}

// fill replaces every parameter of path with a value, and adds the
// required query parameters, or reports the first one it has none for. A
// query parameter is filled like a path parameter (pick), else with the
// spec's example.
//
// An optional query parameter is added only when it names an object
// (namesObject) or has a value declared in .procyon.yaml, and only with a
// value pick finds, never the spec's example: GET /picture?picture_id= is
// then tested on A's picture, and an optional filter (?status=sold) is
// never sent.
func (h *harvest) fill(path string, query []loader.QueryParam, optional ...loader.QueryParam) (filled, error) {
	f := filled{own: true}
	use := func(param, v string, own bool) {
		f.values, f.params = append(f.values, v), append(f.params, param)
		f.own = f.own && own
	}
	var missing string
	f.path = pathParam.ReplaceAllStringFunc(path, func(m string) string {
		name := m[1 : len(m)-1]
		v, own, ok := h.pick(path, name)
		if !ok && missing == "" {
			missing = name
		}
		use(name, v, own)
		return url.PathEscape(v)
	})
	if missing != "" {
		return filled{}, fmt.Errorf("no value for {%s}", missing)
	}
	values := url.Values{}
	for _, q := range query {
		v, own, ok := h.pick(path, q.Name)
		switch {
		case ok:
			use(q.Name, v, own)
		case q.Example != "":
			v = q.Example
			f.examples = append(f.examples, q.Name)
		default:
			return filled{}, fmt.Errorf("no value for query parameter %s", q.Name)
		}
		values.Set(q.Name, v)
	}
	for _, q := range optional {
		if !namesObject(q.Name) && len(h.declared[normalize(q.Name)]) == 0 {
			continue
		}
		v, own, ok := h.pick(path, q.Name)
		if !ok {
			f.unfilled = append(f.unfilled, q.Name)
			continue
		}
		use(q.Name, v, own)
		values.Set(q.Name, v)
	}
	if len(values) > 0 {
		f.path += "?" + values.Encode() // sorted by name, the same on every run
	}
	return f, nil
}
