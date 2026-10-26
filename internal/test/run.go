package test

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
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
	// Timeout is how long one request may take. Zero means defaultTimeout.
	Timeout time.Duration
	// Budget is the most requests a run sends. Zero means defaultBudget.
	Budget int
	// TokenA and TokenB are the test accounts' tokens (PROCYON_USER_A_TOKEN,
	// PROCYON_USER_B_TOKEN). B must not be allowed to touch A's objects.
	TokenA, TokenB string
	// IDs are values of A's objects by path parameter name, for objects A's
	// responses never show (test.ids in .procyon.yaml).
	IDs map[string][]string
	// LoginA and LoginB sign the accounts in when their token is not set.
	LoginA, LoginB *Login
	// Skip lists operations ("GET /createdb") never called, by anyone:
	// those whose side effects would spoil the run (test.skip).
	Skip []string
	// BaseSpec is the spec before the change under test (--base-spec).
	// When set, only operations new or changed since it are tested.
	BaseSpec string
}

const (
	defaultTimeout = 10 * time.Second
	defaultBudget  = 1000

	// maxBody is how much of a body evidence keeps; maxResponse is how much
	// of a response Procyon reads, to find IDs in.
	maxBody     = 200
	maxResponse = 1 << 20

	// minTelling is the shortest value that tells one object from another:
	// "ok", "1" or "yes" could be in anyone's.
	minTelling = 4
)

// Run tests the API at opts.BaseURL against the spec at specPath.
func Run(ctx context.Context, specPath string, opts Options) (lint.Report, error) {
	var missing []string
	if opts.TokenA == "" && opts.LoginA == nil {
		missing = append(missing, EnvTokenA+" (account A)")
	}
	if opts.TokenB == "" && opts.LoginB == nil {
		missing = append(missing, EnvTokenB+" (account B)")
	}
	if len(missing) > 0 {
		return lint.Report{}, fmt.Errorf("set %s: the token of a test account seeded in the API "+
			"(the bare token: Procyon adds \"Bearer \" when the spec asks for it), "+
			"or declare how it logs in under test.accounts in .procyon.yaml", strings.Join(missing, " and "))
	}
	spec, err := lint.Load(specPath, lint.Options{RefRoot: opts.RefRoot})
	if err != nil {
		return lint.Report{}, err
	}
	var changed map[string]bool // nil: test everything
	var baseNote string
	if opts.BaseSpec != "" {
		// A base that does not load (it was broken on main, and this change
		// may be the fix) means testing everything, not failing the run.
		if base, err := lint.Load(opts.BaseSpec, lint.Options{RefRoot: opts.RefRoot}); err != nil {
			baseNote = fmt.Sprintf("--base-spec not used, every operation is tested: %v", err)
		} else {
			changed, baseNote = spec.Changed(base)
		}
	}
	target, err := checkTarget(ctx, opts.BaseURL, lookupHost)
	if err != nil {
		return lint.Report{}, err
	}
	timeout := cmp.Or(opts.Timeout, defaultTimeout)
	c := newClient(target, timeout, cmp.Or(opts.Budget, defaultBudget))

	// TLS first: a server that speaks only an old protocol is reported
	// before anything else can fail on it.
	var findings []lint.Finding
	var notes []lint.Note
	root := lint.Location{File: specPath, Line: 1, Column: 1}
	if target.Scheme == "https" {
		problems, note := checkTLS(ctx, target, timeout)
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
	r.skip = map[string]bool{}
	for _, name := range opts.Skip {
		if !slices.ContainsFunc(ops, func(op lint.Operation) bool { return op.Key() == name }) {
			// A typo must not quietly call what was meant to be skipped.
			notes = append(notes, lint.Note{Location: root, Message: fmt.Sprintf("test.skip lists %q, which is no operation of the spec", name)})
		}
		r.skip[name] = true
	}
	a := caller{name: "A", token: opts.TokenA}
	ofA, err := r.discover(ctx, ops, a, newHarvest(opts.IDs), false)
	if err != nil {
		return lint.Report{}, err
	}
	// What B's own reads show is B's, or shared with B: finding such a value
	// in a response to B proves nothing.
	b := caller{name: "B", token: opts.TokenB}
	ofB, err := r.discover(ctx, ops, b, newHarvest(nil), true)
	if err != nil {
		return lint.Report{}, err
	}
	ofA.identity, ofB.identity = identityMarks(ofA, ofB), identityMarks(ofB, ofA)

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
	broken, hung := false, false
	breakAll := func() error {
		if broken {
			return nil
		}
		broken = true
		for i, f := range toBreak {
			bad, note, noAnswer, err := r.malformed(ctx, f.op, f.path, a)
			if err != nil {
				return err
			}
			findings = append(findings, bad...)
			if note != "" {
				notes = append(notes, lint.Note{Location: f.op.Location, Message: f.op.Key() + ": " + note})
			}
			if noAnswer {
				// A body that hangs the server (a regular expression that
				// backtracks) may keep it busy for minutes: whatever comes
				// next would only time out too.
				hung = true
				for _, rest := range toBreak[i+1:] {
					notes = append(notes, lint.Note{Location: rest.op.Location, Message: rest.op.Key() +
						": malformed input not tested: the server stopped answering after an earlier malformed request"})
				}
				break
			}
		}
		return nil
	}
	unchanged := 0
	for _, op := range ops {
		key := op.Key()
		skipped := lint.Cell{Outcome: lint.Skipped}
		if op.Method == http.MethodDelete {
			if err := breakAll(); err != nil {
				return lint.Report{}, err
			}
		}
		switch {
		case r.skip[key]:
			notes = append(notes, lint.Note{Location: op.Location, Message: key + " not called: listed under test.skip"})
			matrix = append(matrix, lint.MatrixRow{Operation: key, A: skipped, B: skipped, Anonymous: skipped})
			continue
		case hung:
			notes = append(notes, lint.Note{Location: op.Location, Message: key + " not tested: the server stopped answering after a malformed request"})
			matrix = append(matrix, lint.MatrixRow{Operation: key, A: ofA.cells[key], B: skipped, Anonymous: skipped})
			continue
		}
		row := lint.MatrixRow{Operation: key, A: ofA.cells[key]}
		// Unchanged operations are still read as A above, to find IDs for
		// the changed ones; they are just not tested.
		if changed != nil && !changed[key] {
			unchanged++
			row.B, row.Anonymous = lint.Cell{Outcome: lint.Unchanged}, lint.Cell{Outcome: lint.Unchanged}
			matrix = append(matrix, row)
			continue
		}
		f, err := ofA.fill(op.Path)
		if err != nil {
			notes = append(notes, lint.Note{Location: op.Location, Message: fmt.Sprintf(
				"%s not tested: %v in A's responses; declare one under test.ids in .procyon.yaml", key, err)})
			matrix = append(matrix, lint.MatrixRow{Operation: key, A: skipped, B: skipped, Anonymous: skipped})
			continue
		}
		row.Anonymous = lint.Cell{Outcome: lint.Public}
		if !op.Public {
			exchange, err := r.send(ctx, op, f.path, anonymous)
			if err != nil {
				return lint.Report{}, err
			}
			// Only an operation the spec protects can be reached by
			// mistake; one it leaves open is PRC001's business.
			reached := success(exchange) && op.NeedsAuth
			row.Anonymous = cellOf(exchange, reached)
			if reached {
				findings = append(findings, anonymousAccess(op, exchange))
			}
		}
		if op.Method != http.MethodGet && op.Method != http.MethodDelete && !op.Public {
			if op.Body != nil {
				toBreak = append(toBreak, filledOp{op, f.path})
			} else if op.NeedsBody {
				notes = append(notes, lint.Note{Location: op.Location, Message: key +
					": malformed input not tested: it needs a request body and the spec gives no example"})
			}
		}
		if len(f.values) == 0 {
			matrix = append(matrix, row)
			continue // no object in the path: nothing of A's to reach
		}
		var finding *lint.Finding
		var note string
		if !f.own && len(unseen(f.values, ofB.harvest)) == 0 {
			// Every user is shown these IDs (a public list of every book),
			// and nothing says which object is A's: B reaching it proves
			// nothing.
			note = "not tested as B: every user is shown this object's ID and nothing marks it as A's; " +
				"declare one of A's under test.ids in .procyon.yaml"
			row.B = skipped
		} else {
			finding, note, row.B, err = r.otherAccount(ctx, op, f, ofA, ofB, readers, a, b)
			if err != nil {
				return lint.Report{}, err
			}
		}
		matrix = append(matrix, row)
		if finding != nil {
			findings = append(findings, *finding)
		}
		if note != "" {
			notes = append(notes, lint.Note{Location: op.Location, Message: key + ": " + note})
		}
	}
	if err := breakAll(); err != nil {
		return lint.Report{}, err
	}
	if baseNote != "" {
		notes = append(notes, lint.Note{Location: root, Message: baseNote})
	}
	if unchanged > 0 {
		notes = append(notes, lint.Note{Location: root, Message: fmt.Sprintf(
			"%d of %d operations unchanged since %s, not tested", unchanged, len(ops), opts.BaseSpec)})
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

// requestError is a request that could not be sent or answered: its
// message is masked, and errors.As still finds the cause (a timeout).
type requestError struct {
	msg string
	err error
}

func (e *requestError) Error() string { return e.msg }
func (e *requestError) Unwrap() error { return e.err }

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
		Operation: op.Key(),
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
// A read is reached when B's 2xx answer holds values A's answer for the
// same path also held, and that B's own top-level reads never showed:
// A's data, not something every user sees. A write or delete is reached
// when A, reading the object before and after, sees it changed or gone;
// without a GET on the same path, a write counts when its 2xx answer holds
// A's path values, and a delete cannot be told.
func (r *runner) otherAccount(ctx context.Context, op lint.Operation, f filled,
	ofA, ofB *discovery, readers map[string]lint.Operation, a, b caller) (*lint.Finding, string, lint.Cell, error) {
	skipped := lint.Cell{Outcome: lint.Skipped}
	path, values := f.path, f.values
	if op.Method == http.MethodGet && ofA.bodies[path] == nil {
		// Discovery read another object (A's own was not known yet): A
		// reads this one now, to compare with what B gets.
		exchange, body, err := r.sendFull(ctx, op, path, a)
		if err != nil || !success(exchange) {
			return nil, "not tested as B: A's own read of it failed", skipped, err
		}
		ofA.bodies[path] = body
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
		if op.Method != http.MethodDelete && !shown(before, op.Body) {
			return nil, "not tested as B: the GET on this path does not show the fields this write sets, so a change could not be seen", skipped, nil
		}
		if op.Method != http.MethodDelete && holds(before, op.Body) {
			return nil, "not tested as B: A's object already holds the request example's values, so a change could not be seen", skipped, nil
		}
	}
	exchange, body, err := r.sendFull(ctx, op, path, b)
	if err != nil || !success(exchange) {
		return nil, "", cellOf(exchange, false), err
	}
	evidence := []lint.Exchange{exchange}
	var reached bool
	switch {
	case op.Method == http.MethodGet:
		shared := sharedUnseen(body, ofA.bodies[path], ofB.harvest, values)
		// Values B's own object on the same path also holds ("active", a
		// type, a year) are not A's data.
		if own, err := ofB.fill(op.Path); len(shared) > 0 && err == nil && own.own && own.path != path {
			mine, mineBody, err := r.sendFull(ctx, op, own.path, b)
			if err != nil {
				return nil, "", lint.Cell{}, err
			}
			if success(mine) {
				var inMine []string
				if v, ok := decode(mineBody); ok {
					walk(v, func(value string) { inMine = append(inMine, value) })
				}
				shared = slices.DeleteFunc(shared, func(v string) bool { return slices.Contains(inMine, v) })
			}
		}
		reached = len(shared) > 0
	case before == nil && !shows(body, unseen(values, ofB.harvest)):
		// A 2xx to a write Procyon cannot check is not a pass.
		return nil, fmt.Sprintf("not confirmed: B got %d, and without a GET on the same path Procyon cannot tell whether "+
			"A's object changed", exchange.Status), lint.Cell{Outcome: lint.Skipped, Status: exchange.Status}, nil
	default:
		reached = before == nil // a write's answer that holds A's values
	}
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
		Operation: op.Key(),
		Why: fmt.Sprintf("Test account B called this operation on an object of test account A and got %d: "+
			"any user can %s other users' objects by changing the ID in the path.", exchange.Status, what),
		Fix: "On the server, check that the object belongs to the caller (or that the caller may " + what +
			" it) before acting, and answer 404 otherwise.",
		Evidence: evidence,
	}, "", cellOf(exchange, true), nil
}

// shown reports whether a JSON object body has at least one top-level field
// of the JSON object example: a read that can show what a write changes.
func shown(body, example []byte) bool {
	got, ok1 := decode(body)
	want, ok2 := decode(example)
	gotFields, ok3 := got.(map[string]any)
	wantFields, ok4 := want.(map[string]any)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false
	}
	for name := range wantFields {
		if _, ok := gotFields[name]; ok {
			return true
		}
	}
	return false
}

// sharedUnseen lists the field values B's answer and A's answer both hold
// that B's own reads never showed: A's data. Values that prove nothing are
// left out: the path's own values (an API may echo the ID it was asked
// for), booleans, short numbers and short words ("ok", "1", a status any
// object can have).
func sharedUnseen(toB, toA []byte, ofB *harvest, pathValues []string) []string {
	var inA []string
	if v, ok := decode(toA); ok {
		walk(v, func(value string) { inA = append(inA, value) })
	}
	var shared []string
	if v, ok := decode(toB); ok {
		walk(v, func(value string) {
			telling := len(value) >= minTelling && value != "true" && value != "false" && !slices.Contains(pathValues, value)
			if telling && slices.Contains(inA, value) && !ofB.saw(value) && !slices.Contains(shared, value) {
				shared = append(shared, value)
			}
		})
	}
	return shared
}

// identityMarks lists the values that mark one account's own objects, by the
// path they came from: for each read both accounts made that answers one
// object (GET /me, not a list), the fields where the account's answer
// differs from the other's. A list is never used: a counter or a signed URL
// in every item would mark every item. A short value counts only in a field
// named like an identity (id, user, name, email, login): "17" as userId, but
// not "1" as a count.
func identityMarks(mine, theirs *discovery) map[string]string {
	marks := map[string]string{}
	for _, path := range sortedKeys(mine.byPath) {
		if !mine.single[path] || !theirs.single[path] {
			continue
		}
		// Objects in the same place of both answers ({"data": {...}} nests
		// the user one level down), compared field by field.
		for i := range min(len(mine.byPath[path]), len(theirs.byPath[path])) {
			own, other := mine.byPath[path][i], theirs.byPath[path][i]
			for _, field := range sortedKeys(own) {
				v := own[field]
				idLike := strings.HasSuffix(field, "id") || strings.Contains(field, "user") || strings.Contains(field, "name") ||
					strings.Contains(field, "email") || strings.Contains(field, "login")
				if v != other[field] && v != "" && v != "true" && v != "false" && (len(v) >= minTelling || idLike) {
					if _, seen := marks[v]; !seen {
						marks[v] = path
					}
				}
			}
		}
	}
	return marks
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
	tokens []string        // every token, to mask in evidence
	skip   map[string]bool // operations never called (test.skip)
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
		return lint.Exchange{}, nil, &requestError{msg: fmt.Sprintf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...)), err: err}
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	exchange := lint.Exchange{
		Caller: who.name,
		Method: op.Method,
		URL:    mask(req.URL.RequestURI(), r.tokens...),
		Status: resp.StatusCode,
		Body:   r.excerpt(string(got)),
	}
	if body != nil {
		exchange.Sent = r.excerpt(string(op.Body))
	}
	return exchange, got, nil
}

// excerpt is the start of a body for evidence, every token masked. Masked
// before it is cut: a token across the cut would otherwise leave its first
// characters unmasked.
func (r *runner) excerpt(body string) string {
	masked := mask(body, r.tokens...)
	return masked[:min(len(masked), maxBody)]
}

// requestURI is how evidence shows a path sent to the target: with the
// target's own base path, as sendFull records it.
func (r *runner) requestURI(path string) string {
	return mask(strings.TrimSuffix(r.target.Path, "/")+path, r.tokens...)
}

// discover calls who's reads (GET operations) and records what their
// responses show, so other operations' path parameters can be filled with
// who's objects. A read whose path needs a value waits until an earlier
// response has shown one, so it runs as soon as its parameters can be
// filled: GET /notes before GET /notes/{id}. Each pass calls every read
// that has become callable; it stops when a pass calls nothing new.
//
// It also returns what each read got, by operation, for the matrix.
//
// With topLevel, only reads with nothing in their path are called: what a
// caller sees without naming an object. B's discovery is that, so a value B
// "saw" never comes from reading A's objects, which is the very thing being
// tested.
func (r *runner) discover(ctx context.Context, ops []lint.Operation, who caller, h *harvest, topLevel bool) (*discovery, error) {
	d := &discovery{harvest: h, cells: map[string]lint.Cell{}, bodies: map[string][]byte{}}
	done := make([]bool, len(ops))
	for progress := true; progress; {
		progress = false
		for i, op := range ops {
			if done[i] || op.Method != http.MethodGet || (topLevel && strings.Contains(op.Path, "{")) || r.skip[op.Key()] {
				continue
			}
			f, err := h.fill(op.Path)
			if err != nil {
				continue // not yet
			}
			path := f.path
			done[i], progress = true, true
			exchange, body, err := r.sendFull(ctx, op, path, who)
			if err != nil {
				return nil, err
			}
			key := op.Key()
			d.cells[key] = cellOf(exchange, false)
			if success(exchange) {
				h.add(op.Path, body)
				d.bodies[path] = body
			}
		}
	}
	return d, nil
}

// discovery is what one caller's reads showed.
type discovery struct {
	*harvest
	cells  map[string]lint.Cell // what each read got, by operation, for the matrix
	bodies map[string][]byte    // each successful read's response body, by the path sent
}
