package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// harvest is what one test account's responses showed: for each path that
// was called, every JSON object in its responses, as its scalar fields by
// name. Values fill the path parameters of other operations: GET /notes
// shows {"id": "1"}, which fills /notes/{id}.
type harvest struct {
	byPath   map[string][]object // path → the objects seen, breadth first
	declared map[string][]string // normalized parameter name → values from .procyon.yaml
	// identity holds values that mark the account's own objects: what its
	// reads of a path showed and the other account's reads of the same
	// path did not (A's username in GET /me). Set after discovery.
	identity []string
}

// object is one JSON object of a response: its scalar fields, by
// normalized name.
type object map[string]string

func newHarvest(declared map[string][]string) *harvest {
	h := &harvest{byPath: map[string][]object{}, declared: map[string][]string{}}
	// Sorted, so order_id and orderId both declared give the same values
	// on every run.
	for _, name := range sortedKeys(declared) {
		key := normalize(name)
		h.declared[key] = append(h.declared[key], declared[name]...)
	}
	return h
}

// normalize makes orderId, order_id, order-id and OrderID the same name.
func normalize(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
}

// add records the objects of a JSON response body from path. A body that
// is not JSON shows nothing.
func (h *harvest) add(path string, body []byte) {
	v, ok := decode(body)
	if !ok {
		return
	}
	objects(v, func(o object) { h.byPath[path] = append(h.byPath[path], o) })
}

// values lists every scalar value a path's responses showed.
func (h *harvest) values(path string) []string {
	var all []string
	for _, o := range h.byPath[path] {
		for _, name := range sortedKeys(o) {
			all = append(all, o[name])
		}
	}
	return all
}

// decode parses JSON keeping numbers as written: as float64, the ID
// 1234567890123456789 would become 1234567890123456800.
func decode(body []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	return v, true
}

// objects calls fn for every JSON object in v, breadth first: an object
// before the objects inside it, so in [{"id": "o7", "customer": {"id":
// "c1"}}] the order comes before its customer. Keys are visited in sorted
// order, so objects are found in the same order on every run.
func objects(v any, fn func(object)) {
	queue := []any{v}
	for len(queue) > 0 {
		v, queue = queue[0], queue[1:]
		switch v := v.(type) {
		case map[string]any:
			o := object{}
			for _, name := range sortedKeys(v) {
				switch field := v[name].(type) {
				case string:
					o[normalize(name)] = field
				case json.Number:
					o[normalize(name)] = field.String()
				case map[string]any, []any:
					queue = append(queue, field)
				}
			}
			fn(o)
		case []any:
			queue = append(queue, v...)
		}
	}
}

// walk calls fn for every string or number field in v.
func walk(v any, fn func(value string)) {
	objects(v, func(o object) {
		for _, name := range sortedKeys(o) {
			fn(o[name])
		}
	})
}

// pick returns a value for parameter param of path, and whether it is
// known to be the account's own. In order:
//
//  1. a value declared in .procyon.yaml (own, by definition);
//  2. the parent collection's objects' field of the same name, then their
//     "id": GET /notes fills /notes/{id} and /notes/{noteId};
//  3. a field of the same name in any path's objects, paths by name.
//
// Among the objects of 2 or 3, one that holds an identity value (a book
// whose "user" is A's username) wins: it is the account's own. Otherwise
// the first one is taken, not known to be own.
func (h *harvest) pick(path, param string) (value string, own, ok bool) {
	key := normalize(param)
	if values := h.declared[key]; len(values) > 0 {
		return values[0], true, true
	}
	choose := func(objs []object, fields ...string) (string, bool, bool) {
		first := ""
		for _, field := range fields {
			for _, o := range objs {
				v, has := o[field]
				if !has {
					continue
				}
				if first == "" {
					first = v
				}
				for _, value := range o {
					if slices.Contains(h.identity, value) {
						return v, true, true
					}
				}
			}
			if first != "" {
				return first, false, true
			}
		}
		return "", false, false
	}
	parent, _, _ := strings.Cut(path, "/{"+param+"}")
	if v, own, ok := choose(h.byPath[parent], key, "id"); ok {
		return v, own, true
	}
	for _, p := range sortedKeys(h.byPath) {
		if v, own, ok := choose(h.byPath[p], key); ok {
			return v, own, true
		}
	}
	return "", false, false
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// pathParam matches a path parameter: {id}, {orderId}.
var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// filled is a path with every parameter given a value.
type filled struct {
	path   string   // escaped, ready to send: /notes/1
	values []string // the values used, unescaped
	own    bool     // every value is known to be the account's own
}

// fill replaces every parameter of path with a value, or reports the first
// one it has none for.
func (h *harvest) fill(path string) (filled, error) {
	f := filled{own: true}
	var missing string
	f.path = pathParam.ReplaceAllStringFunc(path, func(m string) string {
		name := m[1 : len(m)-1]
		v, own, ok := h.pick(path, name)
		if !ok && missing == "" {
			missing = name
		}
		f.values = append(f.values, v)
		f.own = f.own && own
		return url.PathEscape(v)
	})
	if missing != "" {
		return filled{}, fmt.Errorf("no value for {%s}", missing)
	}
	return f, nil
}

// saw reports whether any response recorded in h showed value.
func (h *harvest) saw(value string) bool {
	for _, objs := range h.byPath {
		for _, o := range objs {
			for _, v := range o {
				if v == value {
					return true
				}
			}
		}
	}
	return false
}

// shows reports whether a JSON body holds one of values in any field: the
// response is about the object those values name.
func shows(body []byte, values []string) bool {
	v, ok := decode(body)
	if !ok {
		return false
	}
	found := false
	walk(v, func(value string) {
		found = found || slices.Contains(values, value)
	})
	return found
}
