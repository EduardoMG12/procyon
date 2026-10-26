package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/report"
)

// When the tests ran but the environment could not be torn down, the
// report is still printed, then the warning, and the exit code is 2.
func TestALeftRunningEnvironmentKeepsTheReport(t *testing.T) {
	cmd := command{
		name: "test",
		run: func(string, invocation) (report.Report, error) {
			return report.Report{Failed: true}, fmt.Errorf("%w: docker compose down: exit status 1", errLeftRunning)
		},
	}
	var stdout, stderr bytes.Buffer
	code := runCommand(cmd, []string{"spec.yaml"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stdout.String(), "FAILED") {
		t.Errorf("stdout %q, want the report", stdout.String())
	}
	if !strings.Contains(stderr.String(), "left running") {
		t.Errorf("stderr %q, want the warning", stderr.String())
	}
}
