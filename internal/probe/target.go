// Package probe runs Procyon's runtime tests: it calls a running, disposable
// copy of an API and reports what the API let each caller do.
//
// It only ever calls loopback and private addresses, where a disposable copy
// lives, never the internet: the check is made once on the --base-url, with
// a clear error, and again on every connection, so a host that resolves to a
// private address first and a public one later is still refused.
package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
// never following a redirect.
type client struct {
	http   *http.Client
	budget int // requests left
	// pin is the SHA-256 of the public key the TLS check saw, once it ran:
	// every later connection must present the same key, so nobody can step
	// in between Procyon and the target during the run.
	pin []byte
}

// maxHeaderBytes caps the response headers Procyon reads; bodies are capped
// by maxResponse.
const maxHeaderBytes = 64 << 10

func newClient(timeout time.Duration, budget int) *client {
	c := &client{budget: budget}
	dialer := &net.Dialer{Timeout: timeout, Control: checkDial}
	transport := &http.Transport{
		MaxResponseHeaderBytes: maxHeaderBytes,
		// No Proxy: an HTTP_PROXY in CI would otherwise carry the requests
		// somewhere else, past checkDial.
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: timeout,
		// A disposable copy on loopback or a private network rarely has a
		// certificate a public CA signed. Its TLS is judged by PRC105
		// instead of refusing every request.
		// TLS 1.0 is allowed too: PRC105 reports it, and the run goes on.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, VerifyConnection: c.checkPin},
	}
	c.http = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A redirect is what the API answered, and is judged as such: a 302
		// to a login page is not a 2xx. Following it, even on the same host,
		// would test another operation, or the same one over plain http.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// errKeyChanged is returned when the target presents another TLS key than
// the one the TLS check saw.
var errKeyChanged = errors.New("the target's TLS key changed during the run")

// checkPin refuses a connection whose key is not the pinned one.
func (c *client) checkPin(cs tls.ConnectionState) error {
	if c.pin == nil {
		return nil // the TLS check has not run, or the target is plain http
	}
	if len(cs.PeerCertificates) == 0 || !bytes.Equal(keyHash(cs.PeerCertificates[0]), c.pin) {
		return errKeyChanged
	}
	return nil
}

// keyHash is the SHA-256 of a certificate's public key: what pinning
// compares, so a renewed certificate with the same key still matches.
func keyHash(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// do sends one request, counting it against the budget.
func (c *client) do(req *http.Request) (*http.Response, error) {
	if c.budget <= 0 {
		return nil, errBudget
	}
	c.budget--
	return c.http.Do(req)
}
