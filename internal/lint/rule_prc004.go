package lint

import (
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/loader"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

var prc004 = lintRule{
	Rule: report.Rule{
		ID:       "PRC004",
		Title:    "Server URL does not use TLS",
		Severity: report.High,
		OWASP:    "API8:2023 Security Misconfiguration",
	},
	check: checkPRC004,
}

// checkPRC004 reports http:// server URLs at every level a spec can declare
// them: the whole spec, a path, an operation.
func checkPRC004(doc *openapi3.T) []report.Finding {
	var findings []report.Finding
	flag := func(server *openapi3.Server, operation string) {
		if server == nil || !plaintext(server) {
			return
		}
		findings = append(findings, report.Finding{
			Location:  loader.LocateField(server.Origin, "url"),
			Operation: operation,
			Element:   server,
			Why:       "Requests to this server travel unencrypted, credentials and tokens included: anyone on the network path can read or change them.",
			Fix:       "Use an https:// URL. Local development servers (localhost, 127.0.0.1, [::1]) are exempt.",
		})
	}
	for _, server := range doc.Servers {
		flag(server, "")
	}
	if doc.Paths != nil {
		for _, item := range doc.Paths.Map() {
			for _, server := range item.Servers {
				flag(server, "")
			}
		}
	}
	loader.ForEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if op.Servers != nil {
			for _, server := range *op.Servers {
				flag(server, method+" "+path)
			}
		}
	})
	return findings
}

// plaintext reports whether any URL the server can take is http:// to a
// host other than the local machine. A URL built from variables
// ("{scheme}://{region}.example.com") is checked with every value the
// variables allow: their enum, or their default when there is no enum.
//
// The scheme and the host are expanded separately, each with only the
// variables that appear in it, so path variables never multiply the work.
// When a part still has too many combinations to check, Procyon assumes the
// worst and reports: a security check must fail closed, never pass by
// running out of patience.
func plaintext(server *openapi3.Server) bool {
	scheme, rest, ok := strings.Cut(server.URL, "://")
	if !ok {
		return false // relative URL: inherits the scheme it is served from
	}
	authority, _, _ := strings.Cut(rest, "/")

	schemes, complete := expand(scheme, server.Variables)
	if complete && !slices.ContainsFunc(schemes, isHTTP) {
		return false
	}
	hosts, complete := expand(authority, server.Variables)
	return !complete || slices.ContainsFunc(hosts, func(authority string) bool {
		u, err := url.Parse("http://" + authority)
		return err == nil && !loopback(u.Hostname())
	})
}

func isHTTP(scheme string) bool {
	return strings.EqualFold(scheme, "http")
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// maxExpansions caps how many strings one part of a templated URL expands
// to, so a hostile spec cannot make Procyon build millions of them.
const maxExpansions = 1024

// expand returns every string template can produce from the variables it
// uses, visiting them in name order so the result never depends on map
// order. complete is false when there were more than maxExpansions.
func expand(template string, vars map[string]*openapi3.ServerVariable) (out []string, complete bool) {
	names := make([]string, 0, len(vars))
	for name := range vars {
		if strings.Contains(template, "{"+name+"}") {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	out = []string{template}
	for _, name := range names {
		values := vars[name].Enum
		if len(values) == 0 {
			values = []string{vars[name].Default}
		}
		if len(out)*len(values) > maxExpansions {
			return nil, false
		}
		var next []string
		for _, s := range out {
			for _, value := range values {
				next = append(next, strings.ReplaceAll(s, "{"+name+"}", value))
			}
		}
		out = next
	}
	return out, true
}
