package test

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// Options control a runtime test.
type Options struct {
	// BaseURL is where the API under test runs. It must be a loopback or
	// private address.
	BaseURL string
	// FailOn and RefRoot work as in a lint.
	FailOn  lint.Severity
	RefRoot string
	// Timeout is how long one request may take. Zero means 10 seconds.
	Timeout time.Duration
	// Budget is the most requests a run sends. Zero means 1000.
	Budget int
	// TokenA and TokenB are the test accounts' tokens (PROCYON_USER_A_TOKEN,
	// PROCYON_USER_B_TOKEN). B must not be allowed to touch A's objects.
	TokenA, TokenB string
	// IDs are values of A's objects by path parameter name, for objects A's
	// responses never show (test.ids in .procyon.yaml).
	IDs map[string][]string
	// LoginA and LoginB sign the accounts in when their token is not set.
	LoginA, LoginB *Login
}

// maxBody is how much of a response body evidence keeps; maxResponse is
// how much of it Procyon reads, to find IDs in.
const (
	maxBody     = 200
	maxResponse = 1 << 20
)

// Run tests the API at opts.BaseURL against the spec at specPath.
func Run(ctx context.Context, specPath string, opts Options) (lint.Report, error) {
	if (opts.TokenA == "" && opts.LoginA == nil) || (opts.TokenB == "" && opts.LoginB == nil) {
		return lint.Report{}, fmt.Errorf("set %s and %s to the tokens of two test accounts seeded in the API "+
			"(the bare token: Procyon adds \"Bearer \" when the spec asks for it), "+
			"or declare how they log in under test.accounts in .procyon.yaml", envTokenA, envTokenB)
	}
	spec, err := lint.Load(specPath, lint.Options{RefRoot: opts.RefRoot})
	if err != nil {
		return lint.Report{}, err
	}
	target, err := checkTarget(ctx, opts.BaseURL, lookupHost)
	if err != nil {
		return lint.Report{}, err
	}
	c := newClient(target, cmp.Or(opts.Timeout, 10*time.Second), cmp.Or(opts.Budget, 1000))

	// TLS first: a server that speaks only an old protocol is reported
	// before anything else can fail on it.
	var findings []lint.Finding
	var notes []lint.Note
	root := lint.Location{File: specPath, Line: 1, Column: 1}
	if target.Scheme == "https" {
		problems, note := checkTLS(ctx, target, cmp.Or(opts.Timeout, 10*time.Second))
		if len(problems) > 0 {
			findings = append(findings, weakTLS(root, target, problems))
		}
		if note != "" {
			notes = append(notes, lint.Note{Location: root, Message: note})
		}
	} else {
		notes = append(notes, lint.Note{Location: root, Message: "TLS not checked: the target is plain http " +
			"(a disposable copy usually is; TLS belongs to the production proxy). PRC105 runs on https targets."})
	}
	r := &runner{client: c, target: target, tokens: []string{opts.TokenA, opts.TokenB}}
	// A token from the environment wins over a login.
	for _, account := range []struct {
		name  string
		token *string
		login *Login
	}{{"A", &opts.TokenA, opts.LoginA}, {"B", &opts.TokenB, opts.LoginB}} {
		if *account.token != "" {
			continue
		}
		if *account.token, err = r.login(ctx, spec, account.name, account.login); err != nil {
			return lint.Report{}, err
		}
		r.tokens = append(r.tokens, *account.token)
	}

	ops := inTestOrder(spec.Operations())
	a := caller{name: "A", token: opts.TokenA}
	ofA, asReads, err := r.discover(ctx, ops, a, newHarvest(opts.IDs))
	if err != nil {
		return lint.Report{}, err
	}
	// What B's own reads show is B's, or shared with B: finding such a value
	// in a response to B proves nothing.
	b := caller{name: "B", token: opts.TokenB}
	ofB, _, err := r.discover(ctx, ops, b, newHarvest(nil))
	if err != nil {
		return lint.Report{}, err
	}

	// readers are the GETs by path: how A checks whether B changed or
	// deleted A's object.
	readers := map[string]lint.Operation{}
	for _, op := range ops {
		if op.Method == http.MethodGet {
			readers[op.Path] = op
		}
	}

	var matrix []lint.MatrixRow
	// Malformed requests (PRC103, PRC104) run as A in their own pass, after
	// every write's B check and before the deletes: an accepted mutation
	// changes A's object, which must not hide what B can do to it.
	var toBreak []filledOp
	broken := false
	breakAll := func() error {
		if broken {
			return nil
		}
		broken = true
		for _, f := range toBreak {
			bad, note, err := r.malformed(ctx, f.op, f.path, a)
			if err != nil {
				return err
			}
			findings = append(findings, bad...)
			if note != "" {
				notes = append(notes, lint.Note{Location: f.op.Location, Message: f.op.Method + " " + f.op.Path + ": " + note})
			}
		}
		return nil
	}
	for _, op := range ops {
		if op.Method == http.MethodDelete {
			if err := breakAll(); err != nil {
				return lint.Report{}, err
			}
		}
		row := lint.MatrixRow{Operation: op.Method + " " + op.Path, A: asReads[op.Method+" "+op.Path]}
		path, values, err := ofA.fill(op.Path)
		if err != nil {
			notes = append(notes, lint.Note{Location: op.Location, Message: fmt.Sprintf(
				"%s %s not tested: %v in A's responses; declare one under test.ids in .procyon.yaml", op.Method, op.Path, err)})
			skipped := lint.Cell{Outcome: lint.Skipped}
			matrix = append(matrix, lint.MatrixRow{Operation: row.Operation, A: skipped, B: skipped, Anonymous: skipped})
			continue
		}
		row.Anonymous = lint.Cell{Outcome: lint.Public}
		if !op.Public {
			exchange, err := r.send(ctx, op, path, anonymous)
			if err != nil {
				return lint.Report{}, err
			}
			row.Anonymous = cellOf(exchange, success(exchange))
			if success(exchange) {
				findings = append(findings, anonymousAccess(op, exchange))
			}
		}
		if op.Method != http.MethodGet && op.Method != http.MethodDelete && !op.Public && op.Body != nil {
			toBreak = append(toBreak, filledOp{op, path}) // after every write's B check, below
		}
		if len(values) == 0 {
			matrix = append(matrix, row)
			continue // no object in the path: nothing of A's to reach
		}
		finding, note, cell, err := r.otherAccount(ctx, op, path, values, ofB, readers, a, b)
		if err != nil {
			return lint.Report{}, err
		}
		row.B = cell
		matrix = append(matrix, row)
		if finding != nil {
			findings = append(findings, *finding)
		}
		if note != "" {
			notes = append(notes, lint.Note{Location: op.Location, Message: op.Method + " " + op.Path + ": " + note})
		}
	}
	if err := breakAll(); err != nil { // when no operation is a delete
		return lint.Report{}, err
	}
	report := spec.Finish(findings, notes, lint.Options{FailOn: opts.FailOn})
	report.Matrix = matrix
	return report, nil
}

// cellOf is the matrix cell of a call: a finding when reached, otherwise
// allowed or denied by its status.
func cellOf(exchange lint.Exchange, reached bool) lint.Cell {
	switch {
	case reached:
		return lint.Cell{Outcome: lint.Reached, Status: exchange.Status}
	case success(exchange):
		return lint.Cell{Outcome: lint.Allowed, Status: exchange.Status}
	}
	return lint.Cell{Outcome: lint.Denied, Status: exchange.Status}
}

// filledOp is an operation with its path filled with A's values.
type filledOp struct {
	op   lint.Operation
	path string
}

// anonymousAccess is a PRC101 finding.
func anonymousAccess(op lint.Operation, exchange lint.Exchange) lint.Finding {
	return lint.Finding{
		Rule:      lint.RuntimeRule("PRC101"),
		Location:  op.Location,
		Operation: op.Method + " " + op.Path,
		Why: fmt.Sprintf("A request with no credentials got %d: anyone who can reach the API can call this operation, "+
			"though the spec says it needs authentication.", exchange.Status),
		Fix: "Make the server answer 401 to requests without valid credentials on this operation. " +
			"If it is meant to be open, mark it x-procyon-public with the reason.",
		Evidence: []lint.Exchange{exchange},
	}
}

// otherAccount calls op as B with A's object in the path and returns a
// PRC102 finding if B reached it, or a note when it cannot tell.
//
// A read is reached when B gets a 2xx holding A's values (see shows). A
// write or delete is reached when A, reading the object before and after,
// sees it changed or gone; without a GET on the same path, a write counts
// when its 2xx answer holds A's values, and a delete cannot be told.
func (r *runner) otherAccount(ctx context.Context, op lint.Operation, path string, values []string,
	ofB *harvest, readers map[string]lint.Operation, a, b caller) (*lint.Finding, string, lint.Cell, error) {
	skipped := lint.Cell{Outcome: lint.Skipped}
	ofAs := unseen(values, ofB)
	if len(ofAs) == 0 {
		return nil, "", lint.Cell{}, nil // every value in the path is one B sees too
	}
	if op.Method != http.MethodGet && op.NeedsBody && op.Body == nil {
		return nil, "not tested as B: it needs a request body and the spec gives no example", skipped, nil
	}
	reader, canRead := readers[op.Path]
	if op.Method == http.MethodDelete && !canRead {
		return nil, "not tested as B: without a GET on the same path, Procyon cannot tell whether a delete worked", skipped, nil
	}

	var before []byte
	if op.Method != http.MethodGet && canRead {
		exchange, body, err := r.sendFull(ctx, reader, path, a)
		if err != nil || !success(exchange) {
			return nil, "not tested as B: A could not read the object first", skipped, err
		}
		before = body
		if op.Method != http.MethodDelete && holds(before, op.Body) {
			return nil, "not tested as B: A's object already holds the request example's values, so a change could not be seen", skipped, nil
		}
	}
	exchange, body, err := r.sendFull(ctx, op, path, b)
	if err != nil || !success(exchange) {
		return nil, "", cellOf(exchange, false), err
	}
	evidence := []lint.Exchange{exchange}
	reached := shows(body, ofAs)
	if before != nil {
		after, afterBody, err := r.sendFull(ctx, reader, path, a)
		if err != nil {
			return nil, "", lint.Cell{}, err
		}
		evidence = append(evidence, after)
		switch {
		case op.Method == http.MethodDelete && (after.Status == http.StatusNotFound || after.Status == http.StatusGone):
			reached = true // gone
		case op.Method == http.MethodDelete && !success(after):
			// A 429 or a 503 says nothing about the object.
			return nil, fmt.Sprintf("not confirmed: after B's delete, A's read got %d", after.Status), skipped, nil
		case op.Method == http.MethodDelete:
			reached = false // still there
		default:
			// Only the fields B sent count: a timestamp or a view counter
			// changes on every read.
			reached = success(after) && holds(afterBody, op.Body)
		}
	}
	if !reached {
		return nil, "", cellOf(exchange, false), nil
	}
	what := map[string]string{http.MethodGet: "read", http.MethodDelete: "delete"}[op.Method]
	if what == "" {
		what = "change"
	}
	return &lint.Finding{
		Rule:      lint.RuntimeRule("PRC102"),
		Location:  op.Location,
		Operation: op.Method + " " + op.Path,
		Why: fmt.Sprintf("Test account B called this operation on an object of test account A and got %d: "+
			"any user can %s other users' objects by changing the ID in the path.", exchange.Status, what),
		Fix: "On the server, check that the object belongs to the caller (or that the caller may " + what +
			" it) before acting, and answer 404 otherwise.",
		Evidence: evidence,
	}, "", cellOf(exchange, true), nil
}

// holds reports whether a JSON object body has every top-level field of
// the JSON object example with the same value. An example that is not an
// object proves nothing either way.
func holds(body, example []byte) bool {
	got, ok1 := decode(body)
	want, ok2 := decode(example)
	gotFields, ok3 := got.(map[string]any)
	wantFields, ok4 := want.(map[string]any)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(wantFields) == 0 {
		return false
	}
	for name, value := range wantFields {
		if !reflect.DeepEqual(gotFields[name], value) {
			return false
		}
	}
	return true
}

func success(exchange lint.Exchange) bool {
	return exchange.Status >= 200 && exchange.Status < 300
}

// unseen keeps the values B's own responses never showed.
func unseen(values []string, ofB *harvest) []string {
	var kept []string
	for _, v := range values {
		if !ofB.saw(v) {
			kept = append(kept, v)
		}
	}
	return kept
}

// inTestOrder orders operations as runtime tests run them: reads, then
// writes, then deletes, so a destructive request never removes what a later
// one needs. Within reads and writes the spec's order (by path, then method)
// is kept; deletes go deepest path first. Every run sends the same requests
// in the same order.
func inTestOrder(ops []lint.Operation) []lint.Operation {
	group := func(method string) int {
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return 0
		case http.MethodDelete:
			return 2
		}
		return 1 // POST, PUT, PATCH and anything else changes something
	}
	ops = slices.Clone(ops)
	slices.SortStableFunc(ops, func(a, b lint.Operation) int {
		if c := cmp.Compare(group(a.Method), group(b.Method)); c != 0 || group(a.Method) != 2 {
			return c
		}
		// Deletes go deepest first: /users/{id}/notes/{noteId} before
		// /users/{id}, whose delete could take the note with it.
		return cmp.Compare(strings.Count(b.Path, "/"), strings.Count(a.Path, "/"))
	})
	return ops
}

// runner holds what every request of a run shares.
type runner struct {
	client *client
	target *url.URL
	tokens []string // every token, to mask in evidence
}

// send calls one operation as who and records the exchange, with every
// token masked. A request that cannot be sent at all (the API is down, the
// budget is used up) stops the run: its findings would be incomplete.
func (r *runner) send(ctx context.Context, op lint.Operation, path string, who caller) (lint.Exchange, error) {
	exchange, _, err := r.sendFull(ctx, op, path, who)
	return exchange, err
}

// sendFull is send, also returning the response body (up to maxResponse).
func (r *runner) sendFull(ctx context.Context, op lint.Operation, path string, who caller) (lint.Exchange, []byte, error) {
	u := *r.target
	u.Path = strings.TrimSuffix(r.target.Path, "/") + path
	var body io.Reader
	if op.Method != http.MethodGet && op.Body != nil {
		body = bytes.NewReader(op.Body)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), body)
	if err != nil {
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	authorize(req, op.Credential, who.token)
	resp, err := r.client.do(req)
	if err != nil {
		// The error may quote the URL, and a query-string token with it.
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...))
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	// Masked before it is cut: a token across the cut would otherwise
	// leave its first characters unmasked.
	excerpt := mask(string(got), r.tokens...)
	excerpt = excerpt[:min(len(excerpt), maxBody)]
	exchange := lint.Exchange{
		Caller: who.name,
		Method: op.Method,
		URL:    mask(req.URL.RequestURI(), r.tokens...),
		Status: resp.StatusCode,
		Body:   excerpt,
	}
	if body != nil {
		sent := mask(string(op.Body), r.tokens...)
		exchange.Sent = sent[:min(len(sent), maxBody)]
	}
	return exchange, got, nil
}

// discover calls who's reads (GET operations) and records what their
// responses show, so other operations' path parameters can be filled with
// who's objects. A read whose path needs a value waits until an earlier
// response has shown one, so it runs as soon as its parameters can be
// filled: GET /notes before GET /notes/{id}. Each pass calls every read
// that has become callable; it stops when a pass calls nothing new.
//
// It also returns what each read got, by operation, for the matrix.
func (r *runner) discover(ctx context.Context, ops []lint.Operation, who caller, h *harvest) (*harvest, map[string]lint.Cell, error) {
	cells := map[string]lint.Cell{}
	done := make([]bool, len(ops))
	for progress := true; progress; {
		progress = false
		for i, op := range ops {
			if done[i] || op.Method != http.MethodGet {
				continue
			}
			path, _, err := h.fill(op.Path)
			if err != nil {
				continue // not yet
			}
			done[i], progress = true, true
			exchange, body, err := r.sendFull(ctx, op, path, who)
			if err != nil {
				return nil, nil, err
			}
			cells[op.Method+" "+op.Path] = cellOf(exchange, false)
			if success(exchange) {
				h.add(op.Path, body)
			}
		}
	}
	return h, cells, nil
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
