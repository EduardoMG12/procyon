package loader

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The total read through $refs is capped, not only each file, so many
// files just under the per-file cap cannot exhaust memory. The limit is
// lowered for the test; the behaviour goes through Load, the package's seam.
func TestRefsHaveATotalBudget(t *testing.T) {
	fakeHome(t)
	defer func(old int64) { maxRefTotal = old }(maxRefTotal)
	maxRefTotal = 100

	dir := t.TempDir()
	item := "get:\n  responses:\n    \"200\":\n      description: OK\n" // 47 bytes
	spec := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n"
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(item), 0o644); err != nil {
			t.Fatal(err)
		}
		spec += "  /" + name + ":\n    $ref: \"./" + name + ".yaml\"\n"
	}
	path := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, anyRule)
	if err == nil || !strings.Contains(err.Error(), "in total") {
		t.Fatalf("Load = %v, want an error about the total read through $refs", err)
	}
}

// The spec itself is capped too.
func TestSpecHasASizeLimit(t *testing.T) {
	defer func(old int64) { maxSpecSize = old }(maxSpecSize)
	maxSpecSize = 10
	path := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(path, []byte("openapi: 3.0.3\ninfo: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, anyRule)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Load = %v, want an error about the spec's size", err)
	}
}

// The number of $refs resolved is capped: each may be parsed again.
func TestTheNumberOfRefsIsCapped(t *testing.T) {
	fakeHome(t)
	defer func(old int) { maxRefReads = old }(maxRefReads)
	maxRefReads = 2

	dir := t.TempDir()
	item := "get:\n  responses:\n    \"200\":\n      description: OK\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(item), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n"
	for _, p := range []string{"one", "two", "three"} {
		spec += "  /" + p + ":\n    $ref: \"./a.yaml\"\n"
	}
	path := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, anyRule)
	if err == nil || !strings.Contains(err.Error(), "more than 2 $refs") {
		t.Fatalf("Load = %v, want an error about the number of $refs", err)
	}
}

// The bytes kin-openapi parses again through $refs are capped too: the
// cache makes reading a file again free, not parsing it, so without this
// budget a small spec could make kin-openapi parse a large file thousands of
// times. Each case parses a padded file again for each response.
func TestRefsParsedAgainHaveABudget(t *testing.T) {
	fakeHome(t)
	defer func(old int64) { maxRefReparsed = old }(maxRefReparsed)
	maxRefReparsed = 100 << 10 // 100 KiB: about ten parses of either file

	padding := "x-padding: \"" + strings.Repeat("x", 10<<10) + "\"\n"
	cases := map[string]string{
		// kin-openapi cannot find x-h in its typed header, so it parses the
		// spec again to look for it.
		"$refs into an x- extension": "description: OK\n" +
			"headers:\n  H:\n    $ref: \"#/components/headers/H/x-h\"\n",
		"$refs to a whole file": "$ref: \"./response.yaml\"\n",
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "response.yaml"), "description: OK\n"+padding)
			spec := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n"
			for i := range 50 {
				spec += "  /p" + strconv.Itoa(i) + ":\n    get:\n      responses:\n        \"200\":\n" +
					indent(response, "          ")
			}
			spec += "components:\n  headers:\n    H:\n      schema:\n        type: string\n" +
				"      x-h:\n        schema:\n          type: string\n" + padding
			path := filepath.Join(dir, "api.yaml")
			writeFile(t, path, spec)
			_, err := Load(path, anyRule)
			if err == nil || !strings.Contains(err.Error(), "parses files again") {
				t.Fatalf("Load = %v, want an error about the bytes parsed again through $refs", err)
			}
		})
	}
}

// A $ref back into the spec from another file is handed the spec, which
// kin-openapi already holds and drops: it must not count, or a large spec
// split this way would be refused.
func TestRefsBackIntoTheSpecAreNotParsedAgain(t *testing.T) {
	fakeHome(t)
	defer func(old int64) { maxRefReparsed = old }(maxRefReparsed)
	maxRefReparsed = 10 // less than the spec

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "get.yaml"), "get:\n  responses:\n    \"200\":\n"+
		"      $ref: \"./api.yaml#/components/responses/OK\"\n")
	path := filepath.Join(dir, "api.yaml")
	writeFile(t, path, "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n"+
		"  /a:\n    $ref: \"./get.yaml\"\n"+
		"components:\n  responses:\n    OK:\n      description: OK\n")
	if _, err := Load(path, anyRule); err != nil {
		t.Fatalf("Load = %v, want no error", err)
	}
}

// indent puts prefix before every line of text.
func indent(text, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSuffix(text, "\n"), "\n", "\n"+prefix) + "\n"
}
