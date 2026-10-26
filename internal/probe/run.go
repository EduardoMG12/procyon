package probe

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/EduardoMG12/procyon/internal/loader"

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
	r := &runner{client: newClient(timeout, cmp.Or(opts.Budget, defaultBudget)), target: target}
	res := &results{root: report.Location{File: specPath, Line: 1, Column: 1}}

	// TLS first: a server that speaks only an old protocol is reported
	// before anything else can fail on it.
	if err := res.tls(ctx, r.client, target, timeout); err != nil {
		return report.Report{}, err
	}
	a, b, err := r.signIn(ctx, spec, opts)
	if err != nil {
		return report.Report{}, err
	}
	ops := inTestOrder(spec.Operations())
	r.skip = res.skipSet(ops, opts.Skip)
	ofA, ofB, created, err := r.discoverAccounts(ctx, ops, a, b, opts.IDs)
	if err != nil {
		return report.Report{}, err
	}

	s := &session{runner: r, res: res, ofA: ofA, ofB: ofB, a: a, b: b, changed: changed, readers: readers(ops)}
	firstDelete := slices.IndexFunc(ops, func(op loader.Operation) bool { return op.Method == http.MethodDelete })
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

	if len(created) > 0 {
		res.note(res.root, "the test accounts created objects of their own to be tested with ("+strings.Join(created, ", ")+")")
	}
	res.note(res.root, baseNote)
	if r.redirects > 0 {
		// A redirect is judged as what the API answered: never followed,
		// never a 2xx. Many of them usually mean the spec's paths and the
		// server's disagree (a trailing slash), and nothing was tested.
		res.note(res.root, fmt.Sprintf("%d answers were redirects (first: %s); Procyon does not follow redirects, "+
			"so those calls were judged on the redirect itself: check that the spec's paths match the server's", r.redirects, r.firstRedirect))
	}
	if s.unchanged > 0 {
		res.note(res.root, fmt.Sprintf("%d of %d operations unchanged since %s, not tested", s.unchanged, len(ops), opts.BaseSpec))
	}
	rep := finish(spec, res.findings, res.notes, opts.FailOn)
	rep.Matrix = res.matrix
	return rep, nil
}

// finish turns a run's findings and notes into its report, the way a lint
// does: sorted, the spec's ignores of runtime rules applied, the fail
// threshold checked. A finding about no operation (PRC105, the target's
// TLS) is about the spec as a whole: an ignore at its root covers it.
func finish(spec *loader.Spec, findings []report.Finding, notes []report.Note, failOn report.Severity) report.Report {
	for i := range findings {
		if findings[i].Operation == "" && findings[i].Element == nil {
			findings[i].Element = spec.Doc()
		}
	}
	rep := report.New(findings, notes, report.IgnoresOf(spec.Ignores(), lint.RuntimeRules()), report.Options{FailOn: failOn})
	rep.Sources = spec.Sources()
	return rep
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
// has none to check, and pins the key it saw for the rest of the run.
// Without a handshake there is no key to pin, so the run stops: carrying
// on unpinned would let someone who blocked the check step in later.
func (res *results) tls(ctx context.Context, c *client, target *url.URL, timeout time.Duration) error {
	if target.Scheme != "https" {
		res.note(res.root, "TLS not checked: the target is plain http "+
			"(a disposable copy usually is; TLS belongs to the production proxy). PRC105 runs on https targets.")
		return nil
	}
	problems, note, key := checkTLS(ctx, target, timeout)
	if key == nil {
		return fmt.Errorf("%s: %s", target.Host, note)
	}
	c.pin = key
	if len(problems) > 0 {
		res.findings = append(res.findings, weakTLS(res.root, target, problems))
	}
	res.note(res.root, note)
	return nil
}

// skipSet is test.skip as a set. An entry that names no operation is a
// note: a typo must not quietly call what was meant to be skipped.
func (res *results) skipSet(ops []loader.Operation, skip []string) map[string]bool {
	set := map[string]bool{}
	for _, name := range skip {
		if !slices.ContainsFunc(ops, func(op loader.Operation) bool { return op.Key() == name }) {
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
func loadSpecs(specPath string, opts Options) (spec *loader.Spec, changed map[string]bool, note string, err error) {
	spec, err = loader.Load(specPath, loader.Options{RefRoot: opts.RefRoot, KnownRule: lint.KnownRule})
	if err != nil || opts.BaseSpec == "" {
		return spec, nil, "", err
	}
	base, err := loader.Load(opts.BaseSpec, loader.Options{RefRoot: opts.RefRoot, KnownRule: lint.KnownRule})
	if err != nil {
		return spec, nil, fmt.Sprintf("--base-spec not used, every operation is tested: %v", err), nil
	}
	changed, note = spec.Changed(base)
	return spec, changed, note, nil
}

// signIn returns the two test accounts with their tokens: from the
// environment, which wins, or from their declared login.
func (r *runner) signIn(ctx context.Context, spec *loader.Spec, opts Options) (a, b caller, err error) {
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

// readers are the GETs by path: how A checks whether B changed or deleted
// A's object.
func readers(ops []loader.Operation) map[string]loader.Operation {
	byPath := map[string]loader.Operation{}
	for _, op := range ops {
		if op.Method == http.MethodGet {
			byPath[op.Path] = op
		}
	}
	return byPath
}

// inTestOrder orders operations as runtime tests run them: reads, then
// writes, then deletes, so a destructive request never removes what a later
// one needs. Within reads and writes the spec's order (by path, then method)
// is kept; deletes go deepest path first. Every run sends the same requests
// in the same order.
func inTestOrder(ops []loader.Operation) []loader.Operation {
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
	slices.SortStableFunc(ops, func(a, b loader.Operation) int {
		if c := cmp.Compare(group(a.Method), group(b.Method)); c != 0 || group(a.Method) != 2 {
			return c
		}
		// Deletes go deepest first: /users/{id}/notes/{noteId} before
		// /users/{id}, whose delete could take the note with it.
		return cmp.Compare(strings.Count(b.Path, "/"), strings.Count(a.Path, "/"))
	})
	return ops
}
