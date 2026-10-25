package test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// harvest is what one test account's responses showed: for each path that
// was called, the values of every field, by field name. Values fill the path
// parameters of other operations: GET /notes shows {"id": "1"}, which fills
// /notes/{id}.
type harvest struct {
	byPath   map[string]map[string][]string // path → normalized field name → values, in the order seen
	declared map[string][]string            // normalized parameter name → values from .procyon.yaml
}

func newHarvest(declared map[string][]string) *harvest {
	h := &harvest{byPath: map[string]map[string][]string{}, declared: map[string][]string{}}
	for name, values := range declared {
		h.declared[normalize(name)] = values
	}
	return h
}

// normalize makes orderId, order_id, order-id and OrderID the same name.
func normalize(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
}

// add records the scalar fields of a JSON response body from path. A body
// that is not JSON shows nothing.
func (h *harvest) add(path string, body []byte) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return
	}
	fields := h.byPath[path]
	if fields == nil {
		fields = map[string][]string{}
		h.byPath[path] = fields
	}
	walk(v, func(name, value string) {
		key := normalize(name)
		for _, seen := range fields[key] {
			if seen == value {
				return
			}
		}
		fields[key] = append(fields[key], value)
	})
}

// walk calls fn for every string or number field in v, at any depth.
func walk(v any, fn func(name, value string)) {
	switch v := v.(type) {
	case map[string]any:
		for _, name := range sortedKeys(v) { // so values are found in the same order every run
			switch field := v[name].(type) {
			case string:
				fn(name, field)
			case float64:
				fn(name, strconv.FormatFloat(field, 'f', -1, 64))
			default:
				walk(v[name], fn)
			}
		}
	case []any:
		for _, item := range v {
			walk(item, fn)
		}
	}
}

// value returns a value for parameter param of path, or false. In order:
//
//  1. the parent collection's field of the same name, then its "id":
//     GET /notes fills /notes/{id} and /notes/{noteId};
//  2. a field of the same name anywhere, for paths sorted by name;
//  3. a value declared in .procyon.yaml.
func (h *harvest) value(path, param string) (string, bool) {
	key := normalize(param)
	parent, _, _ := strings.Cut(path, "/{"+param+"}")
	if fields := h.byPath[parent]; fields != nil {
		for _, field := range []string{key, "id"} {
			if values := fields[field]; len(values) > 0 {
				return values[0], true
			}
		}
	}
	for _, p := range sortedKeys(h.byPath) {
		if values := h.byPath[p][key]; len(values) > 0 {
			return values[0], true
		}
	}
	if values := h.declared[key]; len(values) > 0 {
		return values[0], true
	}
	return "", false
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// pathParam matches a path parameter: {id}, {orderId}.
var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// fill replaces every parameter of path with a value, or reports the first
// one it has none for. It also returns the values used, unescaped.
func (h *harvest) fill(path string) (string, []string, error) {
	var missing string
	var values []string
	filled := pathParam.ReplaceAllStringFunc(path, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := h.value(path, name)
		if !ok && missing == "" {
			missing = name
		}
		values = append(values, v)
		return url.PathEscape(v)
	})
	if missing != "" {
		return "", nil, fmt.Errorf("no value for {%s}", missing)
	}
	return filled, values, nil
}

// saw reports whether any response recorded in h showed value.
func (h *harvest) saw(value string) bool {
	for _, fields := range h.byPath {
		for _, values := range fields {
			if slices.Contains(values, value) {
				return true
			}
		}
	}
	return false
}

// shows reports whether a JSON body holds one of values in any field: the
// response is about the object those values name.
func shows(body []byte, values []string) bool {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	found := false
	walk(v, func(_, value string) {
		found = found || slices.Contains(values, value)
	})
	return found
}
