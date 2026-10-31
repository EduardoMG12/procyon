package probe

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeDocker puts a docker on PATH that logs its arguments and answers
// `compose port` with port, and fails `compose up` when failUp is set.
func fakeDocker(t *testing.T, port string, failUp bool) (log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker is a shell script")
	}
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	fail := ""
	if failUp {
		fail = `case "$*" in *" up "*) echo "service api is unhealthy"; exit 1;; esac`
	}
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" + fail + "\ncase \"$*\" in *\" port \"*) echo " + port + ";; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// Drop "compose --file f --project-name p" to keep what was asked.
		fields := strings.Fields(line)
		out = append(out, strings.Join(fields[5:], " "))
	}
	return out
}

func TestUpFindsThePortAndDownCleansUp(t *testing.T) {
	log := fakeDocker(t, "0.0.0.0:32768", false)
	base, down, err := Up(context.Background(), Compose{File: "compose.yml", Service: "api", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if base != "http://127.0.0.1:32768" {
		t.Errorf("base URL = %q, want http://127.0.0.1:32768 (0.0.0.0 is called on loopback)", base)
	}
	if err := down(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(calls(t, log), " | ")
	if want := "up --detach --wait | port api 8080 | down --volumes --remove-orphans --rmi local"; got != want {
		t.Errorf("docker calls = %q, want %q", got, want)
	}
}

func TestUpFailureShowsDockersOutputAndStillTearsDown(t *testing.T) {
	log := fakeDocker(t, "", true)
	_, down, err := Up(context.Background(), Compose{File: "compose.yml", Service: "api", Port: 8080})
	if err == nil || !strings.Contains(err.Error(), "service api is unhealthy") {
		t.Fatalf("err = %v, want docker's output in it", err)
	}
	if err := down(); err != nil {
		t.Fatal(err)
	}
	if got := calls(t, log); got[len(got)-1] != "down --volumes --remove-orphans --rmi local" {
		t.Errorf("last docker call = %q, want down", got[len(got)-1])
	}
}

// Down runs even when the run's context is cancelled (Ctrl-C).
func TestDownRunsAfterCancel(t *testing.T) {
	log := fakeDocker(t, "127.0.0.1:40000", false)
	ctx, cancel := context.WithCancel(context.Background())
	_, down, err := Up(ctx, Compose{File: "compose.yml", Service: "api", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := down(); err != nil {
		t.Fatalf("down after cancel: %v", err)
	}
	if got := calls(t, log); got[len(got)-1] != "down --volumes --remove-orphans --rmi local" {
		t.Errorf("last docker call = %q, want down", got[len(got)-1])
	}
}
