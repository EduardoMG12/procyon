package probe

import (
	"encoding/json"
	"regexp"
	"unicode"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// personalValue is one value of an answer that is personal data.
type personalValue struct {
	place string // where it is in the answer, as fieldsIn names it: "reviews.email"
	kind  string // lint.Email, lint.Phone or lint.NationalID
	value string
}

// personalValues lists the personal data in a JSON answer, in the order
// the answer shows it: every value whose field's name says it is personal
// data (lint.PersonalDataKind) and whose shape agrees (shaped). Both must:
// an orderNumber of eleven digits is not a phone number, and a phone of
// "n/a" holds none. An answer that is not JSON has none.
func personalValues(body []byte) []personalValue {
	v, ok := decode(body)
	if !ok {
		return nil
	}
	var found []personalValue
	fieldsIn(v, "", "", func(name, place, value string) {
		if kind := lint.PersonalDataKind(name); kind != "" && shaped(kind, value) {
			found = append(found, personalValue{place, kind, value})
		}
	})
	return found
}

// fieldsIn calls fn for every string or number in v, at any depth, with
// the name of the field that holds it and its place in the answer as an
// x-procyon-ignore names it: names joined by dots, lists left out
// ("reviews.email"). A list keeps the name and place of its field, so
// "emails": ["a@b.c"] is the field emails. Keys are visited in sorted
// order, so an answer's fields come in the same order on every run.
func fieldsIn(v any, name, place string, fn func(name, place, value string)) {
	switch v := v.(type) {
	case string:
		fn(name, place, v)
	case json.Number:
		fn(name, place, v.String())
	case []any:
		for _, item := range v {
			fieldsIn(item, name, place, fn)
		}
	case map[string]any:
		for _, key := range sortedKeys(v) {
			inner := key
			if place != "" {
				inner = place + "." + key
			}
			fieldsIn(v[key], key, inner, fn)
		}
	}
}

// The shapes of personal data values. A phone number is written with
// digits, spaces, dashes, dots, parentheses and a leading +; a national ID
// with digits and the separators a CPF (123.456.789-09), an SSN
// (078-05-1120) or an RG (12.345.678-X) has, and the letters of a passport
// (AB123456).
var (
	emailShape      = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	phoneShape      = regexp.MustCompile(`^\+?[0-9 ().-]+$`)
	nationalIDShape = regexp.MustCompile(`^[0-9A-Za-z./ -]+$`)
)

// shaped reports whether value looks like personal data of kind: an
// e-mail address, a phone number of 8 to 15 digits (the most a number can
// have, by E.164), or a national ID of 6 to 14 digits and at most 3
// letters. A placeholder ("n/a", "", "call the shop") or a random ID (a
// UUID has more letters) is not.
func shaped(kind, value string) bool {
	digits, letters := 0, 0
	for _, c := range value {
		switch {
		case unicode.IsDigit(c):
			digits++
		case unicode.IsLetter(c):
			letters++
		}
	}
	switch kind {
	case lint.Email:
		return emailShape.MatchString(value)
	case lint.Phone:
		return phoneShape.MatchString(value) && digits >= 8 && digits <= 15
	case lint.NationalID:
		return nationalIDShape.MatchString(value) && digits >= 6 && digits <= 14 && letters <= 3
	}
	return false
}
