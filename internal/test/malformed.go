package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// mutation is a request body the spec says the API must refuse.
type mutation struct {
	what string // "title as a number", for the finding
	body []byte
}

// mutations breaks the spec's example in fixed ways, one field at a time,
// never randomly: each one a body the schema forbids.
//
//   - a wrong type: the first required field with known types (or the
//     first field with known types) set to a value of none of them;
//   - a missing required field: the first one the example has, left out;
//   - a value outside an enum: the first string enum field;
//   - a string too long: the first string field with a maxLength, one
//     character past it; else the first string field, 100 000 characters.
//
// Fields are in name order. A mutation that comes out equal to the example
// is dropped: it would prove nothing. An example that is not a JSON object
// gives none.
func mutations(example []byte, fields []lint.Field) []mutation {
	v, ok := decode(example)
	base, isObject := v.(map[string]any)
	if !ok || !isObject || len(fields) == 0 {
		return nil
	}
	original, _ := json.Marshal(base)
	var out []mutation
	add := func(what string, change func(map[string]any)) {
		body := maps.Clone(base)
		change(body)
		data, _ := json.Marshal(body) // decoded JSON always encodes back
		if !bytes.Equal(data, original) {
			out = append(out, mutation{what, data})
		}
	}

	if target, ok := wrongTypeTarget(fields); ok {
		value, what := wrongValue(target.Types)
		add(target.Name+" as "+what, func(b map[string]any) { b[target.Name] = value })
	}
	for _, f := range fields {
		if _, inExample := base[f.Name]; f.Required && inExample {
			add("without the required "+f.Name, func(b map[string]any) { delete(b, f.Name) })
			break
		}
	}
	for _, f := range fields {
		if f.Enum && slices.Equal(f.Types, []string{"string"}) {
			add(f.Name+" outside its enum", func(b map[string]any) { b[f.Name] = "procyon-not-in-enum" })
			break
		}
	}
	long := -1
	for i, f := range fields {
		if f.MaxLength != nil && *f.MaxLength < 1<<16 {
			n := int(*f.MaxLength) + 1
			add(fmt.Sprintf("%s of %d characters (maxLength %d)", f.Name, n, *f.MaxLength),
				func(b map[string]any) { b[f.Name] = strings.Repeat("a", n) })
			long = -2
			break
		}
		if long == -1 && f.MaxLength == nil && slices.Equal(f.Types, []string{"string"}) {
			long = i
		}
	}
	if long >= 0 {
		f := fields[long]
		add(f.Name+" of 100000 characters", func(b map[string]any) { b[f.Name] = strings.Repeat("a", 100000) })
	}
	return out
}

// wrongTypeTarget is the first required field whose types are known, else
// the first field whose types are known.
func wrongTypeTarget(fields []lint.Field) (lint.Field, bool) {
	for _, required := range []bool{true, false} {
		for _, f := range fields {
			if len(f.Types) > 0 && (f.Required || !required) {
				return f, true
			}
		}
	}
	return lint.Field{}, false
}

// wrongValue is a value whose JSON type is none of types: a number, else
// text, else a boolean.
func wrongValue(types []string) (any, string) {
	switch {
	case !slices.Contains(types, "integer") && !slices.Contains(types, "number"):
		return 42, "a number"
	case !slices.Contains(types, "string"):
		return "not-a-number", "text"
	}
	return true, "a boolean"
}

// malformed sends op's example as A, then each mutation, and returns a
// PRC103 finding if a mutation crashed the server (5xx) and a PRC104
// finding if one was accepted (2xx). When the example itself fails with a
// 5xx, a crash proves nothing about validation: it says so in a note.
func (r *runner) malformed(ctx context.Context, op lint.Operation, path string, a caller) ([]lint.Finding, string, error) {
	muts := mutations(op.Body, op.Fields)
	if len(muts) == 0 {
		return nil, "", nil
	}
	control, err := r.send(ctx, op, path, a)
	if err != nil {
		return nil, "", err
	}
	if control.Status >= 500 {
		return nil, fmt.Sprintf("malformed input not tested: the spec's own example already gets %d", control.Status), nil
	}
	var crashed, accepted []string
	var crashEvidence, acceptEvidence []lint.Exchange
	for _, m := range muts {
		bad := op
		bad.Body = m.body
		exchange, err := r.send(ctx, bad, path, a)
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			// No answer at all is the worst way to fail: a body that keeps
			// the server busy (a regular expression that backtracks, a
			// loop) takes it down for everyone.
			crashed = append(crashed, m.what+": no answer within the timeout")
			sent := mask(string(m.body), r.tokens...)
			crashEvidence = append(crashEvidence, lint.Exchange{Caller: a.name, Method: op.Method, URL: path,
				Sent: sent[:min(len(sent), maxBody)], Body: "(no answer)"})
			continue
		}
		if err != nil {
			return nil, "", err
		}
		switch {
		case exchange.Status >= 500:
			crashed, crashEvidence = append(crashed, m.what), append(crashEvidence, exchange)
		case success(exchange):
			accepted, acceptEvidence = append(accepted, m.what), append(acceptEvidence, exchange)
		}
	}
	var findings []lint.Finding
	name := op.Method + " " + op.Path
	if len(crashed) > 0 {
		findings = append(findings, lint.Finding{
			Rule: lint.RuntimeRule("PRC103"), Location: op.Location, Operation: name,
			Why: "A request body the spec forbids (" + strings.Join(crashed, "; ") + ") made the server fail with a 5xx: " +
				"it reached code that did not expect it, which can leak errors or be used to take the server down.",
			Fix:      "Validate the request body against the schema before using it, and answer 400 with what is wrong.",
			Evidence: crashEvidence,
		})
	}
	if len(accepted) > 0 {
		findings = append(findings, lint.Finding{
			Rule: lint.RuntimeRule("PRC104"), Location: op.Location, Operation: name,
			Why: "The server accepted a request body the spec forbids (" + strings.Join(accepted, "; ") + "): " +
				"what it stores is not what the spec promises, and the gap is where injection and mass assignment start.",
			Fix:      "Validate the request body against the schema (types, required fields, enums, lengths) and answer 400 otherwise.",
			Evidence: acceptEvidence,
		})
	}
	return findings, "", nil
}
