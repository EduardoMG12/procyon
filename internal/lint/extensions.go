package lint

import (
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// publicKey marks a public operation: one meant to be reachable without
// authentication. Its value is the reason, which is mandatory.
const publicKey = "x-procyon-public"

// publicReason returns why an operation is public, or "" when it is not.
func publicReason(op *openapi3.Operation) string {
	reason, _ := op.Extensions[publicKey].(string)
	return strings.TrimSpace(reason)
}

// checkExtensions rejects malformed Procyon extensions. A typo in one must
// never silently change what Procyon reports, so it stops the run instead.
func checkExtensions(doc *openapi3.T, asGiven func(Location) Location) error {
	var first error
	forEachOperation(doc, func(method, path string, op *openapi3.Operation) {
		if _, marked := op.Extensions[publicKey]; !marked || first != nil {
			return
		}
		if publicReason(op) == "" {
			loc := asGiven(locate(op.Origin))
			first = fmt.Errorf(`%s:%d:%d: %s %s: %s needs a reason, e.g. %s: "Load balancer health check"`,
				loc.File, loc.Line, loc.Column, method, path, publicKey, publicKey)
		}
	})
	return first
}
