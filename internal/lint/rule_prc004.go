package lint

import (
	"net"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc004 = Rule{
	ID:       "PRC004",
	Title:    "Server URL does not use TLS",
	Severity: High,
	OWASP:    "API8:2023 Security Misconfiguration",
	check:    checkPRC004,
}

// checkPRC004 reports http:// server URLs at every level a spec can declare
// them: the whole spec, a path, an operation.
func checkPRC004(doc *openapi3.T) []Finding {
	var findings []Finding
	report := func(server *openapi3.Server, operation string) {
		if server == nil || !plaintext(server) {
			return
		}
		findings = append(findings, Finding{
			Location:  locateField(server.Origin, "url"),
			Operation: operation,
			Why:       "Requests to this server travel unencrypted, credentials and tokens included: anyone on the network path can read or change them.",
			Fix:       "Use an https:// URL. Local development servers (localhost, 127.0.0.1, [::1]) are exempt.",
		})
	}
	for _, server := range doc.Servers {
		report(server, "")
	}
	if doc.Paths != nil {
		for _, item := range doc.Paths.Map() {
			for _, server := range item.Servers {
				report(server, "")
			}
		}
	}
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.Servers != nil {
			for _, server := range *op.Servers {
				report(server, method+" "+path)
			}
		}
	})
	return findings
}

// plaintext reports whether any URL the server can take is http:// to a
// host other than the local machine. A URL built from variables
// ("{scheme}://api.example.com") is checked with every value the variables
// allow: their enum, or their default when there is no enum.
func plaintext(server *openapi3.Server) bool {
	for _, candidate := range expand(server.URL, server.Variables) {
		u, err := url.Parse(candidate)
		if err != nil || !strings.EqualFold(u.Scheme, "http") {
			continue
		}
		if !loopback(u.Hostname()) {
			return true
		}
	}
	return false
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// maxExpansions caps how many URLs a templated server expands to, so a
// hostile spec cannot make Procyon build millions of strings.
// ponytail: 64 covers any real spec; past it the rest goes unchecked.
const maxExpansions = 64

// expand returns every URL the template can produce from its variables.
func expand(template string, vars map[string]*openapi3.ServerVariable) []string {
	urls := []string{template}
	for name, v := range vars {
		values := v.Enum
		if len(values) == 0 {
			values = []string{v.Default}
		}
		var next []string
		for _, u := range urls {
			for _, value := range values {
				if len(next) < maxExpansions {
					next = append(next, strings.ReplaceAll(u, "{"+name+"}", value))
				}
			}
		}
		urls = next
	}
	return urls
}
