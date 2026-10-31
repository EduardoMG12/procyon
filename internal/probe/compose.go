package probe

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Compose is a disposable environment Procyon starts itself from the user's
// compose file, tests, and always tears down.
type Compose struct {
	File    string // docker-compose.yml
	Service string // the service that serves the API
	Port    int    // the API's port inside the container
}

// docker is the command Procyon runs. Tests point PATH at a fake one.
const docker = "docker"

// composeTail is how many lines of docker's output an error shows.
const composeTail = 15

// Up starts the environment with `docker compose up --wait` (the service's
// healthcheck decides when the API is ready) under a project name of its
// own, so it never touches a stack the user already runs. It returns the
// API's base URL on loopback and a down function that removes everything
// the run made: containers, volumes, and the images compose built for it.
// The caller must always call down, even when the run fails or is
// interrupted; down ignores ctx, so it runs after a Ctrl-C.
func Up(ctx context.Context, c Compose) (baseURL string, down func() error, err error) {
	project := fmt.Sprintf("procyon-test-%d", os.Getpid())
	compose := func(ctx context.Context, args ...string) (string, error) {
		full := append([]string{"compose", "--file", c.File, "--project-name", project}, args...)
		cmd := exec.CommandContext(ctx, docker, full...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	down = func() error {
		// A fresh context: the run's may be cancelled already.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		// --rmi local removes only the images compose built and named after
		// the project (procyon-test-<pid>-api): never one the compose file
		// names with `image:`, nor one pulled from a registry.
		if out, err := compose(ctx, "down", "--volumes", "--remove-orphans", "--rmi", "local"); err != nil {
			return fmt.Errorf("docker compose down: %w\n%s", err, tail(out))
		}
		return nil
	}

	if out, err := compose(ctx, "up", "--detach", "--wait"); err != nil {
		return "", down, fmt.Errorf("docker compose up: %w; the environment did not start or never became healthy:\n%s", err, tail(out))
	}
	out, err := compose(ctx, "port", c.Service, strconv.Itoa(c.Port))
	if err != nil {
		return "", down, fmt.Errorf("docker compose port %s %d: %w\n%s", c.Service, c.Port, err, tail(out))
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(firstLine(out)))
	if err != nil {
		return "", down, fmt.Errorf("docker compose port %s %d: %q is not host:port; is the port published?", c.Service, c.Port, strings.TrimSpace(out))
	}
	// Published on every interface: Procyon still calls it on loopback.
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), down, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// tail keeps the last lines of docker's output, where the reason is.
func tail(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-composeTail):], "\n")
}
