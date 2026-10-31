package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Changed returns the operations of s ("GET /notes/{id}") that are new
// since base or whose definition changed: their own fields, their path's
// parameters, the security that applies to them and its schemes, or anything
// they reference, however deep. `procyon test --base-spec` tests only those.
//
// A spec split across files is compared conservatively: every operation
// counts as changed, and why is the note. A $ref into another file is kept
// as text by the loader, so a change inside that file would be missed.
func (s *Spec) Changed(base *Spec) (changed map[string]bool, note string) {
	changed = map[string]bool{}
	if len(s.files.lines) > 1 || len(base.files.lines) > 1 {
		ForEachOperation(s.doc, func(method, path string, op *openapi3.Operation) {
			changed[OperationKey(method, path)] = true
		})
		return changed, "the spec is split across files, which --base-spec cannot compare yet: every operation is tested"
	}
	inBase := newFingerprints(base.doc)
	before := map[string]string{} // operation → its fingerprint in base
	ForEachOperation(base.doc, func(method, path string, op *openapi3.Operation) {
		before[OperationKey(method, path)] = inBase.of(path, op)
	})
	after := newFingerprints(s.doc)
	ForEachOperation(s.doc, func(method, path string, op *openapi3.Operation) {
		key := OperationKey(method, path)
		if old, ok := before[key]; !ok || old != after.of(path, op) {
			changed[key] = true
		}
	})
	return changed, ""
}

// fingerprints computes operations' fingerprints for one document. Each
// referenced node is hashed once, with its own $refs left as written; an
// operation's fingerprint is its own JSON plus the hashes of every node it
// reaches through $refs. Linear in the size of the spec, whatever the
// sharing, and recursive schemas need nothing special: a node is visited
// once.
type fingerprints struct {
	doc    *openapi3.T
	root   any                 // the whole document as plain JSON, for local $refs
	hash   map[string]string   // $ref → hash of its node, once computed
	refsOf map[string][]string // $ref → the $refs inside its node, once found
}

func newFingerprints(doc *openapi3.T) *fingerprints {
	return &fingerprints{doc: doc, root: generic(doc), hash: map[string]string{}, refsOf: map[string][]string{}}
}

// of is the fingerprint of one operation.
func (f *fingerprints) of(path string, op *openapi3.Operation) string {
	security := EffectiveSecurity(f.doc, op)
	var pathParams openapi3.Parameters
	if item := f.doc.Paths.Value(path); item != nil {
		pathParams = item.Parameters
	}
	// Requirements name their schemes instead of referencing them.
	schemes := map[string]any{}
	for _, req := range security {
		for name := range req {
			if f.doc.Components != nil {
				schemes[name] = f.doc.Components.SecuritySchemes[name]
			}
		}
	}
	own := generic(map[string]any{"operation": op, "pathParameters": pathParams, "security": security, "schemes": schemes})

	// Every $ref reachable from the operation, breadth first.
	var refs []string
	seen := map[string]bool{}
	queue := refsIn(own)
	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		if seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
		next, ok := f.refsOf[ref]
		if !ok {
			next = refsIn(f.node(ref))
			f.refsOf[ref] = next
		}
		queue = append(queue, next...)
	}
	slices.Sort(refs)
	parts := []string{canonical(own)}
	for _, ref := range refs {
		parts = append(parts, ref+"="+f.hashOf(ref))
	}
	return strings.Join(parts, "\n")
}

// node is what a local $ref ("#/components/schemas/Note") points to in the
// document, or nil. Another file's $ref has no node here.
func (f *fingerprints) node(ref string) any {
	pointer, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil
	}
	v := f.root
	for _, part := range strings.Split(pointer, "/") {
		if unescaped, err := url.PathUnescape(part); err == nil {
			part = unescaped
		}
		part = unescapePointer(part)
		switch node := v.(type) {
		case map[string]any:
			v = node[part]
		case []any:
			i, err := strconv.Atoi(part) // strict, like the pointer in internal/probe/login.go
			if err != nil || i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
	}
	return v
}

func (f *fingerprints) hashOf(ref string) string {
	if h, ok := f.hash[ref]; ok {
		return h
	}
	sum := sha256.Sum256([]byte(canonical(f.node(ref))))
	h := hex.EncodeToString(sum[:8])
	f.hash[ref] = h
	return h
}

// refsIn lists every $ref string in a plain JSON value.
func refsIn(v any) []string {
	var refs []string
	var collect func(any)
	collect = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				refs = append(refs, ref)
			}
			for _, field := range v {
				collect(field)
			}
		case []any:
			for _, item := range v {
				collect(item)
			}
		}
	}
	collect(v)
	return refs
}

// canonical is v as JSON with sorted keys (encoding/json sorts map keys).
func canonical(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// generic turns a value into plain JSON maps and slices.
func generic(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(data, &out) // what json.Marshal wrote always decodes
	return out
}
