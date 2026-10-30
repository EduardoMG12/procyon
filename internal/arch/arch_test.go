// Package arch holds no code: its test checks the import rules that keep
// Procyon's design honest, so breaking one fails the build instead of
// waiting for a reviewer to notice.
package arch

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/EduardoMG12/procyon/internal/"

// imports lists the imports of a package's non-test files.
func imports(t *testing.T, pkg string) []string {
	t.Helper()
	dir := filepath.Join("..", pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			all = append(all, path)
		}
	}
	return all
}

// Hard rule 7: linting never touches the network. The packages a lint runs
// through import nothing that could open a connection or run a program.
// (kin-openapi itself imports net/http; the loader refuses remote $refs.)
func TestLintNeverImportsTheNetwork(t *testing.T) {
	// net and every net/... package can reach the network (net/http,
	// net/smtp, net/rpc, ...), except net/netip and net/url: they are only
	// values, and parsing an address or a URL opens nothing.
	values := []string{"net/netip", "net/url"}
	for _, pkg := range []string{"lint", "loader", "words", "report", "format"} {
		for _, imp := range imports(t, pkg) {
			network := (imp == "net" || strings.HasPrefix(imp, "net/")) && !slices.Contains(values, imp)
			if network || imp == "crypto/tls" || imp == "os/exec" {
				t.Errorf("internal/%s imports %s", pkg, imp)
			}
		}
	}
}

// Hard rule 8: the core never knows about formats, and formats never decide
// what is a finding. Formats read only the report; the report model
// depends on nothing of Procyon's.
func TestFormatsSeeOnlyTheReport(t *testing.T) {
	for pkg, allowed := range map[string][]string{
		"format": {module + "report"},
		"report": {},
		"words":  {},
	} {
		for _, imp := range imports(t, pkg) {
			if strings.HasPrefix(imp, module) && !slices.Contains(allowed, imp) {
				t.Errorf("internal/%s imports %s", pkg, imp)
			}
			if strings.Contains(imp, ".") && !strings.HasPrefix(imp, module) { // a third-party module
				t.Errorf("internal/%s imports the dependency %s", pkg, imp)
			}
		}
	}
}

// The linter never depends on the runtime tests, and the loader on neither.
// Neither linter nor runtime tests know about formats (hard rule 8).
func TestDependenciesPointOneWay(t *testing.T) {
	for pkg, forbidden := range map[string][]string{
		"lint":   {module + "probe", module + "format"},
		"loader": {module + "lint", module + "probe", module + "format"},
		"probe":  {module + "format"},
		"report": {module + "lint", module + "loader", module + "probe"},
	} {
		for _, imp := range imports(t, pkg) {
			if slices.Contains(forbidden, imp) {
				t.Errorf("internal/%s imports %s", pkg, imp)
			}
		}
	}
}
