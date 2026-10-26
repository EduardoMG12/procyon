package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// tlsProblem is one weakness of an https target's TLS, with what proves it.
type tlsProblem struct {
	what  string // "accepts TLS 1.0"
	proof string // "negotiated TLS 1.0"
}

// checkTLS connects to an https target with crypto/tls and returns what is
// weak: a protocol older than TLS 1.2, a weak cipher suite, and, for a
// certificate a known CA signed, one expired, not yet valid or for another
// host. A self-signed or private-CA certificate is not judged: anyone can
// mint one with any name and dates, and a disposable copy rarely has a
// public one. Every connection goes through checkDial, like the requests.
// note says what could not be checked, or is "".
func checkTLS(ctx context.Context, target *url.URL, timeout time.Duration) (problems []tlsProblem, note string) {
	host := target.Hostname()
	addr := target.Host
	if target.Port() == "" {
		addr = net.JoinHostPort(host, "443")
	}
	handshake := func(cfg *tls.Config) (tls.ConnectionState, error) {
		cfg.ServerName = host
		cfg.InsecureSkipVerify = true // checked below, by hand: self-signed is allowed
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout, Control: checkDial}, Config: cfg}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer conn.Close()
		return conn.(*tls.Conn).ConnectionState(), nil
	}

	// The old protocols are offered every suite Go has, legacy ones too:
	// a server stuck on TLS 1.0 usually speaks only those.
	var every, weak []uint16
	for _, suite := range tls.CipherSuites() {
		every = append(every, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		every, weak = append(every, suite.ID), append(weak, suite.ID)
	}
	for _, old := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if state, err := handshake(&tls.Config{MinVersion: old, MaxVersion: old, CipherSuites: every}); err == nil {
			name := tls.VersionName(state.Version)
			problems = append(problems, tlsProblem{"accepts " + name, "negotiated " + name})
		}
	}
	if state, err := handshake(&tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: weak}); err == nil {
		name := tls.CipherSuiteName(state.CipherSuite)
		problems = append(problems, tlsProblem{"accepts the weak cipher suite " + name, "negotiated " + name})
	}
	state, err := handshake(&tls.Config{MinVersion: tls.VersionTLS10})
	if err != nil {
		return problems, fmt.Sprintf("TLS not fully checked: no handshake with %s (%v)", addr, err)
	}
	if len(state.PeerCertificates) == 0 {
		return problems, fmt.Sprintf("TLS not fully checked: %s presented no certificate", addr)
	}
	leaf := state.PeerCertificates[0]
	if !publiclySigned(state.PeerCertificates) {
		return problems, ""
	}
	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		problems = append(problems, tlsProblem{"presents an expired certificate",
			"certificate expired on " + leaf.NotAfter.UTC().Format(time.DateOnly)})
	case now.Before(leaf.NotBefore):
		problems = append(problems, tlsProblem{"presents a certificate not valid yet",
			"certificate valid from " + leaf.NotBefore.UTC().Format(time.DateOnly)})
	}
	if err := leaf.VerifyHostname(host); err != nil {
		names := slices.Clone(leaf.DNSNames)
		for _, ip := range leaf.IPAddresses {
			names = append(names, ip.String())
		}
		is := "no host name (only a common name, which clients ignore)"
		if len(names) > 0 {
			is = strings.Join(names, ", ")
		}
		problems = append(problems, tlsProblem{"presents a certificate for another host",
			fmt.Sprintf("certificate is for %s, not %s", is, host)})
	}
	return problems, ""
}

// publiclySigned reports whether a known CA (the system's roots) signed the
// chain, setting dates and names aside: those are what checkTLS judges.
func publiclySigned(chain []*x509.Certificate) bool {
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore.Add(time.Minute), // a time the certificate is valid at
	})
	return err == nil
}

// weakTLS is a PRC105 finding about the whole spec's target.
func weakTLS(where lint.Location, target *url.URL, problems []tlsProblem) lint.Finding {
	var whats []string
	var evidence []lint.Exchange
	for _, p := range problems {
		whats = append(whats, p.what)
		evidence = append(evidence, lint.Exchange{Caller: anonymous.name, Method: "TLS", URL: target.Host, Body: p.proof})
	}
	return lint.Finding{
		Rule:     lint.RuntimeRule("PRC105"),
		Location: where,
		Why: "The API's TLS " + strings.Join(whats, "; ") + ": a client can be pushed onto a connection " +
			"that an attacker on the network can read or tamper with.",
		Fix:      "Accept TLS 1.2 and 1.3 only, with modern cipher suites, and serve a current certificate for the API's host name.",
		Evidence: evidence,
	}
}
