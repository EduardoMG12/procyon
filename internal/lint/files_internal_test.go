package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The total read through $refs is capped, not only each file, so many
// files just under the per-file cap cannot exhaust memory. The limit is
// lowered for the test; the behaviour goes through Run, the library's seam.
func TestRefsHaveATotalBudget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
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
	_, err := Run(path, Options{})
	if err == nil || !strings.Contains(err.Error(), "in total") {
		t.Fatalf("Run = %v, want an error about the total read through $refs", err)
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
	_, err := Run(path, Options{})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Run = %v, want an error about the spec's size", err)
	}
}

// The number of $refs resolved is capped: each may be parsed again.
func TestTheNumberOfRefsIsCapped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
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
	_, err := Run(path, Options{})
	if err == nil || !strings.Contains(err.Error(), "more than 2 $refs") {
		t.Fatalf("Run = %v, want an error about the number of $refs", err)
	}
}
