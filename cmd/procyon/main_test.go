package main_test

import (
	"bytes"
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
		{"invalid severity", "fail-on: severe\n", nil, 2, `"severe"`},
		{"invalid YAML", "fail-on: [\n", nil, 2, ".procyon.yaml:"},
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
