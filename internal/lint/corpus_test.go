package lint_test

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
)

var updateCorpus = flag.Bool("update-corpus", false, "rewrite testdata/corpus/counts.txt with the current findings")

const corpus = "../../testdata/corpus"

// corpusSpecs returns every vendored spec, by corpus name (its directory).
func corpusSpecs(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(corpus, "*", "spec.*"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no corpus specs found: %v", err)
	}
	specs := map[string]string{}
	for _, p := range paths {
		specs[filepath.Base(filepath.Dir(p))] = p
	}
	return specs
}

// TestCorpus lints real public specs. None may fail to load, and the
// number of findings per spec and rule is pinned in counts.txt, so a change
// that makes a rule noisier (or quieter) shows up in review.
func TestCorpus(t *testing.T) {
	specs := corpusSpecs(t)
	names := slices.Sorted(func(yield func(string) bool) {
		for name := range specs {
			if !yield(name) {
				return
			}
		}
	})
	var lines []string
	for _, name := range names {
		rep, err := lint.Run(specs[name], lint.Options{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		counts := map[string]int{}
		for _, f := range rep.Findings {
			counts[f.Rule.ID]++
		}
		if len(counts) == 0 {
			lines = append(lines, name+" - 0")
		}
		for _, rule := range slices.Sorted(func(yield func(string) bool) {
			for r := range counts {
				if !yield(r) {
					return
				}
			}
		}) {
			lines = append(lines, fmt.Sprintf("%s %s %d", name, rule, counts[rule]))
		}
	}
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join(corpus, "counts.txt")
	if *updateCorpus {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("findings across the corpus changed. If that is intended, run\n"+
			"  go test ./internal/lint -run TestCorpus -update-corpus\n"+
			"and explain the difference in the PR.\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestKnownBadSpecs checks the answer key: findings Procyon must report on
// APIs that are vulnerable on purpose. A missing one is a false negative.
func TestKnownBadSpecs(t *testing.T) {
	specs := corpusSpecs(t)
	file, err := os.Open(filepath.Join(corpus, "expected.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	found := map[string][]string{} // spec name -> "RULE line:column OPERATION"
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, want, _ := strings.Cut(line, " ")
		if _, ok := found[name]; !ok {
			path, ok := specs[name]
			if !ok {
				t.Fatalf("expected.txt names %q, which is not in the corpus", name)
			}
			rep, err := lint.Run(path, lint.Options{})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			found[name] = []string{}
			for _, f := range rep.Findings {
				found[name] = append(found[name], fmt.Sprintf("%s %d:%d %s", f.Rule.ID, f.Location.Line, f.Location.Column, f.Operation))
			}
		}
		if !slices.Contains(found[name], want) {
			t.Errorf("%s: missing expected finding %q (false negative)", name, want)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
