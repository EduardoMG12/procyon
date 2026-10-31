package probe

import (
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
	single   map[string]bool     // path → its response is one JSON object (GET /me), not a list
	declared map[string][]string // normalized parameter name → values from .procyon.yaml
	// identity holds values that mark the account's own objects, by the
	// path they came from: what the account's GET /me showed and the other
	// account's did not (its username). Set after discovery.
	identity map[string]string
	// seen holds every value any response showed, for saw: a set, so
	// asking costs the same with 10 values or 100 000.
	seen map[string]bool
}

// object is one JSON object of a response: its scalar fields, by
// normalized name.
type object map[string]string

func newHarvest(declared map[string][]string) *harvest {
	h := &harvest{byPath: map[string][]object{}, single: map[string]bool{}, declared: map[string][]string{}, seen: map[string]bool{}}
	// Sorted, so order_id and orderId both declared give the same values
	// on every run.
	for _, name := range sortedKeys(declared) {
		key := normalize(name)
		h.declared[key] = append(h.declared[key], declared[name]...)
	}
	return h
}

// separators are what normalize drops from a name.
var separators = strings.NewReplacer("_", "", "-", "")

// normalize makes orderId, order_id, order-id and OrderID the same name.
func normalize(name string) string {
	return strings.ToLower(separators.Replace(name))
}

// add records the objects of a JSON response body from path. A body that
// is not JSON shows nothing.
func (h *harvest) add(path string, body []byte) {
	v, ok := decode(body)
	if !ok {
		return
	}
	// Whether a path answers one object (GET /me) is what its first answer
	// said: a created object recorded later under a list's path must not
	// make the list look like one.
	if _, known := h.single[path]; !known {
		_, isObject := v.(map[string]any)
		h.single[path] = isObject
	}
	objects(v, func(o object) {
		h.byPath[path] = append(h.byPath[path], o)
		for _, value := range o {
			h.seen[value] = true
		}
	})
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
//  1. the parent collection's objects' field of the same name, then their
//     "id": GET /notes fills /notes/{id} and /notes/{noteId};
//  2. a field of the same name in any path's objects, paths by name;
//  3. a value declared in .procyon.yaml, which is the account's own.
//
// Among the objects of 1 or 2, one that holds an identity value from
// another path (a book whose "user" is the username GET /me showed) wins:
// it is the account's own. Otherwise the first one is taken, not known to
// be own, and a declared value, when there is one, is preferred to it.
func (h *harvest) pick(path, param string) (value string, own, ok bool) {
	key := normalize(param)
	choose := func(from string, fields ...string) (string, bool, bool) {
		first := ""
		for _, field := range fields {
			for _, o := range h.byPath[from] {
				v, has := o[field]
				if !has {
					continue
				}
				if first == "" {
					first = v
				}
				for _, value := range o {
					if source, mark := h.identity[value]; mark && source != from {
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
	v, own, ok := choose(parent, key, "id")
	for _, p := range sortedKeys(h.byPath) {
		if ok {
			break
		}
		v, own, ok = choose(p, key)
	}
	if declared := h.declared[key]; len(declared) > 0 && !own {
		return declared[0], true, true
	}
	return v, own, ok
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
	return h.seen[value]
}

// sawAllFor reports whether h's responses showed every one of values as
// the value of its own parameter of path (sawFor): values are a filled
// path's, one per parameter, in order. An ID seen for another resource
// does not count: menu item 4 says nothing about order 4. A value with no
// parameter of the path to match was not seen.
func (h *harvest) sawAllFor(path string, values []string) bool {
	params := pathParam.FindAllStringSubmatch(path, -1) // {"{id}", "id"} for each
	for i, v := range values {
		if i >= len(params) || !h.sawFor(path, params[i][1], v) {
			return false
		}
	}
	return true
}

// sawFor reports whether h's responses showed value where pick would
// look for parameter param of path: in the parent collection's objects,
// under the parameter's name or "id", or in any object under the
// parameter's name, unless that name is just "id": "id" alone does not say
// which resource the value belongs to, where orderId does.
func (h *harvest) sawFor(path, param, value string) bool {
	key := normalize(param)
	holds := func(o object, field string) bool {
		v, has := o[field]
		return has && v == value
	}
	parent, _, _ := strings.Cut(path, "/{"+param+"}")
	for _, o := range h.byPath[parent] {
		if holds(o, key) || holds(o, "id") {
			return true
		}
	}
	if key == "id" {
		return false
	}
	for _, objects := range h.byPath {
		if slices.ContainsFunc(objects, func(o object) bool { return holds(o, key) }) {
			return true
		}
	}
	return false
}
