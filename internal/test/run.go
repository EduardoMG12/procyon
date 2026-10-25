package test

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
}

// maxBody is how much of a response body evidence keeps; maxResponse is
// how much of it Procyon reads, to find IDs in.
const (
	maxBody     = 200
	maxResponse = 1 << 20
)

// Run tests the API at opts.BaseURL against the spec at specPath.
func Run(ctx context.Context, specPath string, opts Options) (lint.Report, error) {
	if opts.TokenA == "" || opts.TokenB == "" {
		return lint.Report{}, fmt.Errorf("set %s and %s to the tokens of two test accounts seeded in the API "+
			"(the bare token: Procyon adds \"Bearer \" when the spec asks for it)", envTokenA, envTokenB)
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
	r := &runner{client: c, target: target, tokens: []string{opts.TokenA, opts.TokenB}}

	ops := inTestOrder(spec.Operations())
	a := caller{name: "A", token: opts.TokenA}
	ofA, err := r.discover(ctx, ops, a, newHarvest(opts.IDs))
	if err != nil {
		return lint.Report{}, err
	}
	// What B's own reads show is B's, or shared with B: finding such a value
	// in a response to B proves nothing.
	b := caller{name: "B", token: opts.TokenB}
	ofB, err := r.discover(ctx, ops, b, newHarvest(nil))
	if err != nil {
		return lint.Report{}, err
	}

	var findings []lint.Finding
	var notes []lint.Note
	for _, op := range ops {
		path, values, err := ofA.fill(op.Path)
		if err != nil {
			notes = append(notes, lint.Note{Location: op.Location, Message: fmt.Sprintf(
				"%s %s not tested: %v in A's responses; declare one under test.ids in .procyon.yaml", op.Method, op.Path, err)})
			continue
		}
		if !op.Public {
			exchange, err := r.send(ctx, op, path, anonymous)
			if err != nil {
				return lint.Report{}, err
			}
			if success(exchange) {
				findings = append(findings, anonymousAccess(op, exchange))
			}
		}
		// B reads A's object: only reads for now, writes and deletes are #77.
		if op.Method != http.MethodGet || len(values) == 0 {
			continue
		}
		exchange, body, err := r.sendFull(ctx, op, path, b)
		if err != nil {
			return lint.Report{}, err
		}
		if ofAs := unseen(values, ofB); success(exchange) && len(ofAs) > 0 && shows(body, ofAs) {
			findings = append(findings, otherAccount(op, exchange))
		}
	}
	return spec.Finish(findings, notes, lint.Options{FailOn: opts.FailOn}), nil
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

// otherAccount is a PRC102 finding.
func otherAccount(op lint.Operation, exchange lint.Exchange) lint.Finding {
	return lint.Finding{
		Rule:      lint.RuntimeRule("PRC102"),
		Location:  op.Location,
		Operation: op.Method + " " + op.Path,
		Why: fmt.Sprintf("Test account B asked for an object of test account A and got %d with A's object: "+
			"any user can read other users' objects by changing the ID in the path.", exchange.Status),
		Fix: "On the server, check that the object belongs to the caller (or that the caller may see it) " +
			"before returning it, and answer 404 otherwise.",
		Evidence: []lint.Exchange{exchange},
	}
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
// one needs. Within each group the spec's order (by path, then method) is
// kept, so every run sends the same requests in the same order.
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
	slices.SortStableFunc(ops, func(a, b lint.Operation) int { return cmp.Compare(group(a.Method), group(b.Method)) })
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
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), nil)
	if err != nil {
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
	}
	authorize(req, op.Credential, who.token)
	resp, err := r.client.do(req)
	if err != nil {
		// The error may quote the URL, and a query-string token with it.
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return lint.Exchange{}, nil, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	excerpt := body[:min(len(body), maxBody)]
	return lint.Exchange{
		Caller: who.name,
		Method: op.Method,
		URL:    mask(req.URL.String(), r.tokens...),
		Status: resp.StatusCode,
		Body:   mask(string(excerpt), r.tokens...),
	}, body, nil
}

// discover calls who's reads (GET operations) and records what their
// responses show, so other operations' path parameters can be filled with
// who's objects. A read whose path needs a value waits until an earlier
// response has shown one, so it runs as soon as its parameters can be
// filled: GET /notes before GET /notes/{id}. Each pass calls every read
// that has become callable; it stops when a pass calls nothing new.
func (r *runner) discover(ctx context.Context, ops []lint.Operation, who caller, h *harvest) (*harvest, error) {
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
				return nil, err
			}
			if exchange.Status >= 200 && exchange.Status < 300 {
				h.add(op.Path, body)
			}
		}
	}
	return h, nil
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
