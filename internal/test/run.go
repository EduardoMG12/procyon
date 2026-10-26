package test

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/report"
)

// Options control a runtime test.
type Options struct {
	// BaseURL is where the API under test runs. It must be a loopback or
	// private address.
	BaseURL string
	// FailOn and RefRoot work as in a lint.
	FailOn  report.Severity
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

// Run tests the API at opts.BaseURL against the spec at specPath, in this
// order:
//
//  1. load the spec, and the base spec for --base-spec (loadSpecs);
//  2. check the target is loopback or private, and its TLS (checkTLS);
//  3. sign the test accounts in (signIn);
//  4. read as A and as B to find their objects (discoverAccounts);
//  5. test every read and write: anonymously, then B on A's objects
//     (testOperation);
//  6. send A's writes malformed bodies (malformedPass);
//  7. test every delete, unless the server stopped answering in 6.
//
// Deletes come last so a destructive request never removes what a later
// one needs, and malformed bodies come after B's writes so an accepted one
// never hides what B could do to A's object.
func Run(ctx context.Context, specPath string, opts Options) (report.Report, error) {
	if err := needAccounts(opts); err != nil {
		return report.Report{}, err
	}
	spec, changed, baseNote, err := loadSpecs(specPath, opts)
	if err != nil {
		return report.Report{}, err
	}
	target, err := checkTarget(ctx, opts.BaseURL, lookupHost)
	if err != nil {
		return report.Report{}, err
	}
	timeout := cmp.Or(opts.Timeout, defaultTimeout)
	r := &runner{client: newClient(target, timeout, cmp.Or(opts.Budget, defaultBudget)), target: target}
	res := &results{root: report.Location{File: specPath, Line: 1, Column: 1}}

	// TLS first: a server that speaks only an old protocol is reported
	// before anything else can fail on it.
	res.tls(ctx, target, timeout)
	a, b, err := r.signIn(ctx, spec, opts)
	if err != nil {
		return report.Report{}, err
	}
	ops := inTestOrder(spec.Operations())
	r.skip = res.skipSet(ops, opts.Skip)
	ofA, ofB, err := r.discoverAccounts(ctx, ops, a, b, opts.IDs)
	if err != nil {
		return report.Report{}, err
	}

	s := &session{runner: r, res: res, ofA: ofA, ofB: ofB, a: a, b: b, changed: changed, readers: readers(ops)}
	firstDelete := slices.IndexFunc(ops, func(op lint.Operation) bool { return op.Method == http.MethodDelete })
	if firstDelete < 0 {
		firstDelete = len(ops)
	}
	for _, op := range ops[:firstDelete] {
		if err := s.testOperation(ctx, op); err != nil {
			return report.Report{}, err
		}
	}
	noAnswer, err := s.malformedPass(ctx)
	if err != nil {
		return report.Report{}, err
	}
	for _, op := range ops[firstDelete:] {
		if noAnswer {
			s.skipAfterHang(op)
			continue
		}
		if err := s.testOperation(ctx, op); err != nil {
			return report.Report{}, err
		}
	}

	res.note(res.root, baseNote)
	if s.unchanged > 0 {
		res.note(res.root, fmt.Sprintf("%d of %d operations unchanged since %s, not tested", s.unchanged, len(ops), opts.BaseSpec))
	}
	rep := spec.Finish(res.findings, res.notes, lint.Options{FailOn: opts.FailOn})
	rep.Matrix = res.matrix
	return rep, nil
}

// results collects what a run reports.
type results struct {
	root     report.Location // the spec's first line, for notes about the whole run
	findings []report.Finding
	notes    []report.Note
	matrix   []report.MatrixRow
}

// note adds a note, unless message is empty.
func (res *results) note(where report.Location, message string) {
	if message != "" {
		res.notes = append(res.notes, report.Note{Location: where, Message: message})
	}
}

// tls checks an https target's TLS (PRC105), or notes that an http one
// has none to check.
func (res *results) tls(ctx context.Context, target *url.URL, timeout time.Duration) {
	if target.Scheme != "https" {
		res.note(res.root, "TLS not checked: the target is plain http "+
			"(a disposable copy usually is; TLS belongs to the production proxy). PRC105 runs on https targets.")
		return
	}
	problems, note := checkTLS(ctx, target, timeout)
	if len(problems) > 0 {
		res.findings = append(res.findings, weakTLS(res.root, target, problems))
	}
	res.note(res.root, note)
}

// skipSet is test.skip as a set. An entry that names no operation is a
// note: a typo must not quietly call what was meant to be skipped.
func (res *results) skipSet(ops []lint.Operation, skip []string) map[string]bool {
	set := map[string]bool{}
	for _, name := range skip {
		if !slices.ContainsFunc(ops, func(op lint.Operation) bool { return op.Key() == name }) {
			res.note(res.root, fmt.Sprintf("test.skip lists %q, which is no operation of the spec", name))
		}
		set[name] = true
	}
	return set
}

// needAccounts checks both test accounts have a token or a login.
func needAccounts(opts Options) error {
	var missing []string
	if opts.TokenA == "" && opts.LoginA == nil {
		missing = append(missing, EnvTokenA+" (account A)")
	}
	if opts.TokenB == "" && opts.LoginB == nil {
		missing = append(missing, EnvTokenB+" (account B)")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("set %s: the token of a test account seeded in the API "+
		"(the bare token: Procyon adds \"Bearer \" when the spec asks for it), "+
		"or declare how it logs in under test.accounts in .procyon.yaml", strings.Join(missing, " and "))
}

// loadSpecs loads the spec and, for --base-spec, which of its operations
// changed (nil: test everything). A base that does not load (it was broken
// on main, and this change may be the fix) means testing everything, with
// a note, not failing the run.
func loadSpecs(specPath string, opts Options) (spec *lint.Spec, changed map[string]bool, note string, err error) {
	spec, err = lint.Load(specPath, lint.Options{RefRoot: opts.RefRoot})
	if err != nil || opts.BaseSpec == "" {
		return spec, nil, "", err
	}
	base, err := lint.Load(opts.BaseSpec, lint.Options{RefRoot: opts.RefRoot})
	if err != nil {
		return spec, nil, fmt.Sprintf("--base-spec not used, every operation is tested: %v", err), nil
	}
	changed, note = spec.Changed(base)
	return spec, changed, note, nil
}

// signIn returns the two test accounts with their tokens: from the
// environment, which wins, or from their declared login.
func (r *runner) signIn(ctx context.Context, spec *lint.Spec, opts Options) (a, b caller, err error) {
	a = caller{name: "A", token: opts.TokenA}
	b = caller{name: "B", token: opts.TokenB}
	for _, account := range []struct {
		who   *caller
		login *Login
	}{{&a, opts.LoginA}, {&b, opts.LoginB}} {
		if account.who.token == "" {
			if account.who.token, err = r.login(ctx, spec, account.who.name, account.login); err != nil {
				return a, b, err
			}
		}
		r.tokens = append(r.tokens, account.who.token)
	}
	return a, b, nil
}

// discoverAccounts reads as A, then as B, and marks which values are each
// one's own (identityMarks). B reads only paths with nothing in them: what
// B is shown without naming an object, so a value B "saw" never comes from
// reading A's objects, which is the very thing being tested.
func (r *runner) discoverAccounts(ctx context.Context, ops []lint.Operation, a, b caller, ids map[string][]string) (ofA, ofB *discovery, err error) {
	if ofA, err = r.discover(ctx, ops, a, newHarvest(ids), false); err != nil {
		return nil, nil, err
	}
	if ofB, err = r.discover(ctx, ops, b, newHarvest(nil), true); err != nil {
		return nil, nil, err
	}
	ofA.identity, ofB.identity = identityMarks(ofA, ofB), identityMarks(ofB, ofA)
	return ofA, ofB, nil
}

// readers are the GETs by path: how A checks whether B changed or deleted
// A's object.
func readers(ops []lint.Operation) map[string]lint.Operation {
	byPath := map[string]lint.Operation{}
	for _, op := range ops {
		if op.Method == http.MethodGet {
			byPath[op.Path] = op
		}
	}
	return byPath
}

// session is one run's testing phase: what discovery found, and what is
// left for the malformed pass.
type session struct {
	*runner
	res      *results
	ofA, ofB *discovery
	a, b     caller
	changed  map[string]bool // nil: every operation is tested
	readers  map[string]lint.Operation
	// toBreak are the writes the malformed pass will send bad bodies to,
	// with their path filled with A's object.
	toBreak   []filledOp
	unchanged int
}

var skipped = report.Cell{Outcome: report.Skipped}

// testOperation tests one operation: anonymously (PRC101), then as B on
// A's object (PRC102), and queues a write for the malformed pass. Each ends
// as a row of the matrix.
func (s *session) testOperation(ctx context.Context, op lint.Operation) error {
	key := op.Key()
	row := report.MatrixRow{Operation: key, A: s.ofA.cells[key]}
	switch {
	case s.skip[key]:
		s.res.note(op.Location, key+" not called: listed under test.skip")
		s.res.matrix = append(s.res.matrix, report.MatrixRow{Operation: key, A: skipped, B: skipped, Anonymous: skipped})
		return nil
	case s.changed != nil && !s.changed[key]:
		// Still read as A during discovery, to find IDs for the changed
		// operations; just not tested.
		s.unchanged++
		row.B, row.Anonymous = report.Cell{Outcome: report.Unchanged}, report.Cell{Outcome: report.Unchanged}
		s.res.matrix = append(s.res.matrix, row)
		return nil
	}
	f, err := s.ofA.fill(op.Path)
	if err != nil {
		s.res.note(op.Location, fmt.Sprintf("%s not tested: %v in A's responses; declare one under test.ids in .procyon.yaml", key, err))
		s.res.matrix = append(s.res.matrix, report.MatrixRow{Operation: key, A: skipped, B: skipped, Anonymous: skipped})
		return nil
	}
	if row.Anonymous, err = s.anonymous(ctx, op, f.path); err != nil {
		return err
	}
	s.queueMalformed(op, f.path)
	if len(f.values) > 0 { // an object in the path: one of A's to reach
		if row.B, err = s.asB(ctx, op, f); err != nil {
			return err
		}
	}
	s.res.matrix = append(s.res.matrix, row)
	return nil
}

// anonymous calls op with no credentials. Only an operation the spec
// protects can be reached by mistake (PRC101); one it leaves open is
// PRC001's business. Public operations are not called.
func (s *session) anonymous(ctx context.Context, op lint.Operation, path string) (report.Cell, error) {
	if op.Public {
		return report.Cell{Outcome: report.Public}, nil
	}
	exchange, err := s.send(ctx, op, path, anonymous)
	if err != nil {
		return report.Cell{}, err
	}
	reached := success(exchange) && op.NeedsAuth
	if reached {
		s.res.findings = append(s.res.findings, anonymousAccess(op, exchange))
	}
	return cellOf(exchange, reached), nil
}

// asB tests B on A's object in the path (PRC102).
func (s *session) asB(ctx context.Context, op lint.Operation, f filled) (report.Cell, error) {
	if !f.own && len(unseen(f.values, s.ofB.harvest)) == 0 {
		// Every user is shown these IDs (a public list of every book), and
		// nothing says which object is A's: B reaching it proves nothing.
		s.res.note(op.Location, op.Key()+": not tested as B: every user is shown this object's ID and nothing marks it as A's; "+
			"declare one of A's under test.ids in .procyon.yaml")
		return skipped, nil
	}
	v, err := s.otherAccount(ctx, op, f)
	if err != nil {
		return report.Cell{}, err
	}
	if v.finding != nil {
		s.res.findings = append(s.res.findings, *v.finding)
	}
	if v.note != "" {
		s.res.note(op.Location, op.Key()+": "+v.note)
	}
	return v.cell, nil
}

// queueMalformed keeps a non-public write for the malformed pass, or notes
// why it cannot be sent malformed bodies.
func (s *session) queueMalformed(op lint.Operation, path string) {
	if op.Method == http.MethodGet || op.Method == http.MethodDelete || op.Public {
		return
	}
	switch {
	case op.Body != nil:
		s.toBreak = append(s.toBreak, filledOp{op, path})
	case op.NeedsBody:
		s.res.note(op.Location, op.Key()+": malformed input not tested: it needs a request body and the spec gives no example")
	}
}

// malformedPass sends malformed bodies to the queued writes, as A
// (PRC103, PRC104). noAnswer is true when one got no answer at all: a body
// that hangs the server (a regular expression that backtracks) may keep it
// busy for minutes, so nothing more is sent.
func (s *session) malformedPass(ctx context.Context) (noAnswer bool, err error) {
	for i, f := range s.toBreak {
		bad, note, noAnswer, err := s.malformed(ctx, f.op, f.path, s.a)
		if err != nil {
			return false, err
		}
		s.res.findings = append(s.res.findings, bad...)
		if note != "" {
			s.res.note(f.op.Location, f.op.Key()+": "+note)
		}
		if noAnswer {
			for _, rest := range s.toBreak[i+1:] {
				s.res.note(rest.op.Location, rest.op.Key()+
					": malformed input not tested: the server stopped answering after an earlier malformed request")
			}
			return true, nil
		}
	}
	return false, nil
}

// skipAfterHang notes an operation left untested because the server
// stopped answering.
func (s *session) skipAfterHang(op lint.Operation) {
	key := op.Key()
	s.res.note(op.Location, key+" not tested: the server stopped answering after a malformed request")
	s.res.matrix = append(s.res.matrix, report.MatrixRow{Operation: key, A: s.ofA.cells[key], B: skipped, Anonymous: skipped})
}

// cellOf is the matrix cell of a call: a finding when reached, otherwise
// allowed or denied by its status.
func cellOf(exchange report.Exchange, reached bool) report.Cell {
	switch {
	case reached:
		return report.Cell{Outcome: report.Reached, Status: exchange.Status}
	case success(exchange):
		return report.Cell{Outcome: report.Allowed, Status: exchange.Status}
	}
	return report.Cell{Outcome: report.Denied, Status: exchange.Status}
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
func anonymousAccess(op lint.Operation, exchange report.Exchange) report.Finding {
	return report.Finding{
		Rule:      lint.RuntimeRule("PRC101"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("A request with no credentials got %d: anyone who can reach the API can call this operation, "+
			"though the spec says it needs authentication.", exchange.Status),
		Fix: "Make the server answer 401 to requests without valid credentials on this operation. " +
			"If it is meant to be open, mark it x-procyon-public with the reason.",
		Evidence: []report.Exchange{exchange},
	}
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

func success(exchange report.Exchange) bool {
	return exchange.Status >= 200 && exchange.Status < 300
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
func (r *runner) send(ctx context.Context, op lint.Operation, path string, who caller) (report.Exchange, error) {
	exchange, _, err := r.sendFull(ctx, op, path, who)
	return exchange, err
}

// sendFull is send, also returning the response body (up to maxResponse).
func (r *runner) sendFull(ctx context.Context, op lint.Operation, path string, who caller) (report.Exchange, []byte, error) {
	u := *r.target
	u.Path = strings.TrimSuffix(r.target.Path, "/") + path
	var body io.Reader
	if op.Method != http.MethodGet && op.Body != nil {
		body = bytes.NewReader(op.Body)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), body)
	if err != nil {
		return report.Exchange{}, nil, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	authorize(req, op.Credential, who.token)
	resp, err := r.client.do(req)
	if err != nil {
		// The error may quote the URL, and a query-string token with it.
		return report.Exchange{}, nil, &requestError{msg: fmt.Sprintf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...)), err: err}
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return report.Exchange{}, nil, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	exchange := report.Exchange{
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
	d := &discovery{harvest: h, cells: map[string]report.Cell{}, bodies: map[string][]byte{}}
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
	cells  map[string]report.Cell // what each read got, by operation, for the matrix
	bodies map[string][]byte      // each successful read's response body, by the path sent
}
