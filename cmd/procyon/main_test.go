package main_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// procyon is the path to a binary built once for all tests.
var procyon string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "procyon-test")
	if err != nil {
		panic(err)
	}
	procyon = filepath.Join(dir, "procyon")
	if runtime.GOOS == "windows" {
		procyon += ".exe"
	}
	build := exec.Command("go", "build", "-o", procyon, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	return runIn(t, "", args...)
}

// runIn runs procyon with dir as its working directory ("" keeps the
// test's), which is where it looks for .procyon.yaml.
func runIn(t *testing.T, dir string, args ...string) result {
	t.Helper()
	cmd := exec.Command(procyon, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running procyon: %v", err)
	}
	return result{code, stdout.String(), stderr.String()}
}

func spec(name string) string {
	return filepath.Join("..", "..", "testdata", "specs", name)
}

func TestLintSpecWithoutFindingsExitsZero(t *testing.T) {
	r := run(t, "lint", spec("prc001-global-security.yaml"))
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", r.code, r.stderr)
	}
}

func TestLintBadInputExitsTwoWithOneLine(t *testing.T) {
	r := run(t, "lint", spec("invalid-yaml.yaml"))
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing", r.stdout)
	}
	if lines := strings.Count(r.stderr, "\n"); lines != 1 {
		t.Errorf("stderr has %d lines, want 1: %q", lines, r.stderr)
	}
	if want := "invalid-yaml.yaml:7:10:"; !strings.Contains(r.stderr, want) {
		t.Errorf("stderr %q does not contain %q", r.stderr, want)
	}
}

// Valid JSON skips the YAML syntax check for speed; a JSON spec the YAML
// parser refuses (a duplicate key) must still get its exact error.
func TestJSONWithADuplicateKeyGetsTheYAMLError(t *testing.T) {
	r := run(t, "lint", spec("invalid-json-duplicate-key.json"))
	want := `invalid-json-duplicate-key.json:3:3: mapping key "openapi" already defined at [2:3]`
	if r.code != 2 || !strings.Contains(r.stderr, want) {
		t.Errorf("exit %d, stderr %q; want 2 and %q", r.code, r.stderr, want)
	}
}

func TestUsageErrorsExitTwoAndShowUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown command", []string{"scan"}},
		{"lint without a spec", []string{"lint"}},
		{"lint with two specs", []string{"lint", "a.yaml", "b.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.args...)
			if r.code != 2 {
				t.Errorf("exit code = %d, want 2", r.code)
			}
			if !strings.Contains(r.stderr, "Usage:") {
				t.Errorf("stderr does not show usage: %q", r.stderr)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	r := run(t, "--version")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", r.code, r.stderr)
	}
	if !strings.HasPrefix(r.stdout, "procyon ") {
		t.Errorf("stdout = %q, want it to start with %q", r.stdout, "procyon ")
	}
}

func TestHelpExitsZeroAndShowsUsage(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "help"} {
		t.Run(arg, func(t *testing.T) {
			r := run(t, arg)
			if r.code != 0 {
				t.Errorf("exit code = %d, want 0", r.code)
			}
			if !strings.Contains(r.stdout, "Usage:") {
				t.Errorf("stdout does not show usage: %q", r.stdout)
			}
		})
	}
}

func TestLintFindingsExitOneAndPrintThem(t *testing.T) {
	r := run(t, "lint", spec("prc001-no-auth.yaml"))
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", r.code, r.stderr)
	}
	for _, want := range []string{"high", "PRC001", "prc001-no-auth.yaml:7:5", "GET /orders", "docs/rules/PRC001.md"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout does not contain %q:\n%s", want, r.stdout)
		}
	}
}

func TestFailOnSetsTheThreshold(t *testing.T) {
	high := spec("prc001-no-auth.yaml") // one high finding
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"default fails on high", []string{"lint", high}, 1},
		{"critical lets high pass", []string{"lint", "--fail-on", "critical", high}, 0},
		{"flag after the spec", []string{"lint", high, "--fail-on", "critical"}, 0},
		{"low still fails on high", []string{"lint", "--fail-on=low", high}, 1},
		{"nothing after -- is a flag", []string{"lint", "--", high, "--fail-on", "critical"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := run(t, tt.args...); r.code != tt.want {
				t.Errorf("exit code = %d, want %d; stderr: %s", r.code, tt.want, r.stderr)
			}
		})
	}
}

func TestFailOnRejectsUnknownSeverity(t *testing.T) {
	r := run(t, "lint", "--fail-on", "severe", spec("prc001-no-auth.yaml"))
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, `"severe"`) || !strings.Contains(r.stderr, "critical, high, medium, low") {
		t.Errorf("stderr does not name the bad value and the valid ones: %q", r.stderr)
	}
}

func TestConfigFile(t *testing.T) {
	high, err := filepath.Abs(spec("prc001-no-auth.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		config string
		args   []string
		code   int
		stderr string // substring expected in stderr, if any
	}{
		{"fail-on from the file", "fail-on: critical\n", nil, 0, ""},
		{"flag wins over the file", "fail-on: critical\n", []string{"--fail-on", "high"}, 1, ""},
		{"unknown key is an error", "fail_on: critical\n", nil, 2, "fail_on"},
		{"ignores do not belong here", "ignores: []\n", nil, 2, "ignores"},
		{"invalid severity points at the file", "fail-on: severe\n", nil, 2, `.procyon.yaml: fail-on: unknown severity "severe"`},
		{"invalid YAML", "fail-on: [\n", nil, 2, ".procyon.yaml:"},
		{"unknown format", "format: html\n", nil, 2, `.procyon.yaml: format: unknown format "html"`},
		{"output without a path", "output: [json]\n", nil, 2, `.procyon.yaml: output: "json": want format=path`},
		{"login without a token pointer", "test:\n  accounts:\n    a:\n      login:\n        operation: POST /login\n", nil, 2, ".procyon.yaml:5:18: test.accounts.a.login needs operation"},
		{"unknown key in a login", "test:\n  accounts:\n    b:\n      login:\n        url: /login\n", nil, 2, "url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".procyon.yaml"), []byte(tt.config), 0o644); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"lint"}, tt.args...)
			r := runIn(t, dir, append(args, high)...)
			if r.code != tt.code {
				t.Errorf("exit code = %d, want %d; stderr: %s", r.code, tt.code, r.stderr)
			}
			if !strings.Contains(r.stderr, tt.stderr) {
				t.Errorf("stderr %q does not contain %q", r.stderr, tt.stderr)
			}
		})
	}
}

func TestConfigFileFormats(t *testing.T) {
	high, err := filepath.Abs(spec("prc001-no-auth.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := "format: json\noutput:\n  - markdown=summary.md\n"
	if err := os.WriteFile(filepath.Join(dir, ".procyon.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runIn(t, dir, "lint", high)
	if !strings.HasPrefix(r.stdout, "{") {
		t.Errorf("stdout is not the json format from the file: %q", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.md")); err != nil {
		t.Errorf("the output from the file was not written: %v", err)
	}

	// Flags win: --format replaces format, and one --output replaces the
	// file's whole list.
	if err := os.Remove(filepath.Join(dir, "summary.md")); err != nil {
		t.Fatal(err)
	}
	r = runIn(t, dir, "lint", "--format", "terminal", "--output", "sarif=procyon.sarif", high)
	if strings.HasPrefix(r.stdout, "{") {
		t.Errorf("--format terminal did not win over the file: %q", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "procyon.sarif")); err != nil {
		t.Errorf("--output was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.md")); err == nil {
		t.Error("--output added to the file's outputs instead of replacing them")
	}
}

func TestNoColorWhenStdoutIsNotATerminal(t *testing.T) {
	r := run(t, "lint", spec("prc001-no-auth.yaml"))
	if strings.Contains(r.stdout, "\x1b[") {
		t.Errorf("stdout to a pipe contains ANSI escape codes: %q", r.stdout)
	}
}

func TestFormatJSONOnStdout(t *testing.T) {
	r := run(t, "lint", "--format", "json", spec("prc001-no-auth.yaml"))
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1 (same as the terminal format); stderr: %s", r.code, r.stderr)
	}
	var got struct {
		Version  int `json:"version"`
		Findings []struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	if got.Version != 1 || len(got.Findings) != 1 || got.Findings[0].Rule.ID != "PRC001" {
		t.Errorf("unexpected JSON: %+v", got)
	}
}

func TestOutputWritesExtraFormatsToFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	r := run(t, "lint", "--output", "json="+out, spec("prc001-no-auth.yaml"))
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "PRC001") || strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
		t.Errorf("stdout should still be the terminal format: %q", r.stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Errorf("%s is not JSON", out)
	}
}

func TestBadFormatsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--output", "json"},
		{"--output", "xml=x.xml"},
		{"--output", "json=" + filepath.Join(t.TempDir(), "missing", "dir", "r.json")},
	} {
		r := run(t, append(append([]string{"lint"}, args...), spec("prc001-no-auth.yaml"))...)
		if r.code != 2 {
			t.Errorf("%v: exit code = %d, want 2; stderr: %s", args, r.code, r.stderr)
		}
	}
}

// A failed run must not leave an earlier run's report behind for CI to
// publish as if it were current.
func TestOutputIsNeverStale(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(out, []byte(`{"stale": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run(t, "lint", "--output", "json="+out, spec("invalid-yaml.yaml"))
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	data, err := os.ReadFile(out)
	if err == nil && strings.Contains(string(data), "stale") {
		t.Errorf("%s still holds the previous run's report", out)
	}
}

// An output that cannot be written is found before linting, so nothing is
// printed and no other output is half written.
func TestUnwritableOutputFailsBeforeLinting(t *testing.T) {
	good := filepath.Join(t.TempDir(), "good.json")
	bad := filepath.Join(t.TempDir(), "missing", "dir", "r.json")
	r := run(t, "lint", "--output", "json="+good, "--output", "json="+bad, spec("prc001-no-auth.yaml"))
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if r.stdout != "" {
		t.Errorf("printed a report although an output could not be written: %q", r.stdout)
	}
	if data, err := os.ReadFile(good); err == nil && len(data) > 0 {
		t.Errorf("%s was written although the run stopped", good)
	}
}

func TestOutputSARIF(t *testing.T) {
	out := filepath.Join(t.TempDir(), "procyon.sarif")
	r := run(t, "lint", "--output", "sarif="+out, spec("prc001-no-auth.yaml"))
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", r.code, r.stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil || log.Version != "2.1.0" {
		t.Fatalf("not SARIF 2.1.0: %v\n%s", err, data)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].RuleID != "PRC001" {
		t.Errorf("unexpected results: %+v", log.Runs)
	}
}

func TestOutputMarkdown(t *testing.T) {
	out := filepath.Join(t.TempDir(), "summary.md")
	r := run(t, "lint", "--output", "markdown="+out, spec("prc001-no-auth.yaml"))
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", r.code, r.stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "## Procyon: ❌ failed") || !strings.Contains(string(data), "PRC001") {
		t.Errorf("unexpected summary:\n%s", data)
	}
}

// A monorepo whose specs share files from a sibling folder allows it with
// --ref-root, or ref-root in .procyon.yaml.
func TestRefRoot(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, "common", "orders.yaml"), "get:\n  security: []\n  responses:\n    \"200\":\n      description: OK\n")
	write(filepath.Join(repo, "specs", "api.yaml"), "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"../common/orders.yaml\"\n")
	spec := filepath.Join("specs", "api.yaml")

	if r := runIn(t, repo, "lint", spec); r.code != 2 || !strings.Contains(r.stderr, "--ref-root") {
		t.Errorf("without --ref-root: exit %d, stderr %q; want 2 and a hint about --ref-root", r.code, r.stderr)
	}
	if r := runIn(t, repo, "lint", "--ref-root", ".", spec); r.code != 1 {
		t.Errorf("with --ref-root: exit %d, want 1 (PRC001 found); stderr: %s", r.code, r.stderr)
	}
	write(filepath.Join(repo, ".procyon.yaml"), "ref-root: .\n")
	if r := runIn(t, repo, "lint", spec); r.code != 1 {
		t.Errorf("with ref-root in .procyon.yaml: exit %d, want 1; stderr: %s", r.code, r.stderr)
	}
}

// An --output path that is a symbolic link is refused: a committed link
// named like a report would make Procyon write over what it points at.
func TestOutputRefusesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "README.md")
	if err := os.WriteFile(target, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "procyon.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	r := run(t, "lint", "--output", "markdown="+link, spec("prc001-no-auth.yaml"))
	if r.code != 2 || !strings.Contains(r.stderr, "a symbolic link") {
		t.Errorf("exit %d, stderr %q; want 2 and the link refused", r.code, r.stderr)
	}
	if data, _ := os.ReadFile(target); string(data) != "keep me" {
		t.Errorf("the link's target was written: %q", data)
	}
}
