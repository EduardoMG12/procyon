package probe

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

// harvest is what one test account's responses showed: for each path that
// was called, every JSON object in its responses, as its scalar fields by
// name. Values fill the path parameters of other operations (fill.go):
// GET /notes shows {"id": "1"}, which fills /notes/{id}.
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
	objects(v, func(o object) { h.byPath[path] = append(h.byPath[path], o) })
	walk(v, func(value string) { h.seen[value] = true })
}

// objects calls fn for every JSON object in v, breadth first: an object
// before the objects inside it, so in [{"id": "o7", "customer": {"id":
// "c1"}}] the order comes before its customer. Keys are visited in sorted
// order, so objects are found in the same order on every run. An object
// holds only its own string and number fields: the values of a list
// ("tags": ["x"]) are no field's one value, so they fill no parameter.
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

// walk calls fn for every string or number in v, at any depth, the values
// of lists too ({"tags": ["x"]} holds "x"): the same values PRC106's
// fieldsIn reads.
func walk(v any, fn func(value string)) {
	fieldsIn(v, "", "", func(_, _, value string) { fn(value) })
}

// sortedKeys is m's keys in order, so a map is walked the same way on
// every run.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
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
	parent, _ := parentOf(path, param) // param is one of path's: sawAllFor
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
