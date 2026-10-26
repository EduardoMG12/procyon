// Package test runs Procyon's runtime tests: it calls a running, disposable
// copy of an API and reports what the API let each caller do.
//
// It only ever calls loopback and private addresses, where a disposable copy
// lives, never the internet: the check is made once on the --base-url, with
// a clear error, and again on every connection, so a host that resolves to a
// private address first and a public one later is still refused.
package test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// allowed reports whether addr is a loopback or private address (127.0.0.0/8,
// ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7).
func allowed(addr netip.Addr) bool {
	addr = addr.Unmap() // ::ffff:8.8.8.8 is 8.8.8.8
	return addr.IsLoopback() || addr.IsPrivate()
}

// lookupFunc resolves a host name, like net.DefaultResolver.LookupNetIP;
// tests pass a fake one.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// checkTarget parses a --base-url and refuses it unless it is http or https
// and every address its host resolves to is allowed. There is no way to skip
// this: Procyon never tests a system that is not a disposable copy.
func checkTarget(ctx context.Context, raw string, lookup lookupFunc) (*url.URL, error) {
	target, err := url.Parse(raw)
	// url.Parse refuses some inputs without a scheme ("127.0.0.1:8080") and
	// reads others as a path ("localhost"): both get the same hint.
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("--base-url %q: want an http:// or https:// URL", raw)
	}
	host := target.Hostname()
	if host == "" {
		return nil, fmt.Errorf("--base-url %q: no host", raw)
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("--base-url %q: %w", raw, err)
	}
	for _, addr := range addrs {
		if !allowed(addr) {
			return nil, fmt.Errorf("--base-url %q: %s resolves to %s, which is not a loopback or private address; "+
				"procyon test only calls a disposable copy of your API, never one on the internet", raw, host, addr)
		}
	}
	return target, nil
}

// errNotAllowed is returned when a connection would leave the allowed
// addresses.
var errNotAllowed = errors.New("not a loopback or private address")

// checkDial is a net.Dialer's Control: it runs after the host is resolved
// and before connecting, with the address actually dialled.
func checkDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !allowed(addr) {
		return fmt.Errorf("connecting to %s: %w", addr, errNotAllowed)
	}
	return nil
}

// errBudget is returned once a run has sent all the requests it may.
var errBudget = errors.New("request budget used up")

// client sends a run's requests: one at a time, each with a timeout, at most
// budget of them, never through a proxy, never to a disallowed address and
// never following a redirect to another host.
type client struct {
	http   *http.Client
	budget int // requests left
}

func newClient(target *url.URL, timeout time.Duration, budget int) *client {
	dialer := &net.Dialer{Timeout: timeout, Control: checkDial}
	transport := &http.Transport{
		// No Proxy: an HTTP_PROXY in CI would otherwise carry the requests
		// somewhere else, past checkDial.
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: timeout,
		// A disposable copy on loopback or a private network rarely has a
		// certificate a public CA signed. Its TLS is judged by PRC105
		// instead of refusing every request.
		// TLS 1.0 is allowed too: PRC105 reports it, and the run goes on.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	return &client{
		budget: budget,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// The redirect response itself is what the API answered;
				// following it to another host would test something else.
				if req.URL.Host != target.Host || len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// do sends one request, counting it against the budget.
func (c *client) do(req *http.Request) (*http.Response, error) {
	if c.budget <= 0 {
		return nil, errBudget
	}
	c.budget--
	return c.http.Do(req)
}
