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
}

// maxBody is how much of a response body evidence keeps.
const maxBody = 200

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

	var findings []lint.Finding
	var notes []lint.Note
	for _, op := range inTestOrder(spec.Operations()) {
		if strings.Contains(op.Path, "{") {
			notes = append(notes, lint.Note{Location: op.Location,
				Message: fmt.Sprintf("%s %s not tested yet: its path needs a value Procyon cannot fill", op.Method, op.Path)})
			continue
		}
		if op.Public {
			continue
		}
		exchange, err := r.send(ctx, op, anonymous)
		if err != nil {
			return lint.Report{}, err
		}
		if exchange.Status >= 200 && exchange.Status < 300 {
			findings = append(findings, anonymousAccess(op, exchange))
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
func (r *runner) send(ctx context.Context, op lint.Operation, who caller) (lint.Exchange, error) {
	u := *r.target
	u.Path = strings.TrimSuffix(r.target.Path, "/") + op.Path
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), nil)
	if err != nil {
		return lint.Exchange{}, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
	}
	authorize(req, op.Credential, who.token)
	resp, err := r.client.do(req)
	if err != nil {
		// The error may quote the URL, and a query-string token with it.
		return lint.Exchange{}, fmt.Errorf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return lint.Exchange{}, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	return lint.Exchange{
		Caller: who.name,
		Method: op.Method,
		URL:    mask(req.URL.String(), r.tokens...),
		Status: resp.StatusCode,
		Body:   mask(string(body), r.tokens...),
	}, nil
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
