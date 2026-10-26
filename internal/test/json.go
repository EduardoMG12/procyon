package test

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// The few ways runtime tests look into JSON bodies.

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

// decodeObject parses a JSON body that is an object.
func decodeObject(body []byte) (map[string]any, bool) {
	v, ok := decode(body)
	fields, isObject := v.(map[string]any)
	return fields, ok && isObject
}

// valuesIn lists every string and number value in a JSON body, at any
// depth, or none when it is not JSON.
func valuesIn(body []byte) []string {
	var values []string
	if v, ok := decode(body); ok {
		walk(v, func(value string) { values = append(values, value) })
	}
	return values
}

// mentionsAny reports whether a JSON body holds one of values in any field.
func mentionsAny(body []byte, values []string) bool {
	for _, v := range valuesIn(body) {
		for _, want := range values {
			if v == want {
				return true
			}
		}
	}
	return false
}

// hasAnyFieldOf reports whether a JSON object body has at least one
// top-level field of the JSON object example: a read that can show what a
// write sets.
func hasAnyFieldOf(body, example []byte) bool {
	got, ok1 := decodeObject(body)
	want, ok2 := decodeObject(example)
	if !ok1 || !ok2 {
		return false
	}
	for name := range want {
		if _, ok := got[name]; ok {
			return true
		}
	}
	return false
}

// hasAllValuesOf reports whether a JSON object body has every top-level
// field of the JSON object example, with the same value. An example that
// is not an object, or is empty, proves nothing either way.
func hasAllValuesOf(body, example []byte) bool {
	got, ok1 := decodeObject(body)
	want, ok2 := decodeObject(example)
	if !ok1 || !ok2 || len(want) == 0 {
		return false
	}
	for name, value := range want {
		if !reflect.DeepEqual(got[name], value) {
			return false
		}
	}
	return true
}
