package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/EduardoMG12/procyon/internal/probe"
	"github.com/EduardoMG12/procyon/internal/report"
)

// testFlags are procyon test's own flags.
type testFlags struct {
	baseURL, compose, service, baseSpec string
	port                                int
}

func testCommand() command {
	var tf testFlags
	return command{
		name: "test",
		flags: func(f *flag.FlagSet) {
			f.StringVar(&tf.baseURL, "base-url", "", "")
			f.StringVar(&tf.compose, "compose", "", "")
			f.StringVar(&tf.service, "service", "", "")
			f.IntVar(&tf.port, "port", 0, "")
			f.StringVar(&tf.baseSpec, "base-spec", "", "")
		},
		run:    func(spec string, in invocation) (report.Report, error) { return runTest(spec, in, tf) },
		inputs: func() []string { return []string{tf.baseSpec} },
	}
}

// runTest starts the environment when --compose asks for one, runs the
// runtime tests and always tears the environment down, even on Ctrl-C.
func runTest(spec string, in invocation, tf testFlags) (rep report.Report, err error) {
	switch {
	case tf.compose != "" && tf.baseURL != "":
		return report.Report{}, errors.New("--compose and --base-url: give one, not both")
	case tf.compose != "" && (tf.service == "" || tf.port == 0):
		return report.Report{}, errors.New("--compose needs --service (the service that serves the API) and --port (its port in the container)")
	case tf.compose == "" && tf.baseURL == "":
		return report.Report{}, errors.New("--compose or --base-url is required: where the copy of your API under test runs")
	case tf.compose == "" && (tf.service != "" || tf.port != 0):
		return report.Report{}, errors.New("--service and --port go with --compose; with --base-url, the URL says where the API is")
	}
	// A base spec that does not load is a note (the change may have broken
	// it); a path that does not exist is a typo, which would quietly test
	// every operation instead of the changed ones.
	if tf.baseSpec != "" {
		if _, err := os.Stat(tf.baseSpec); err != nil {
			return report.Report{}, fmt.Errorf("--base-spec: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	baseURL := tf.baseURL
	if tf.compose != "" {
		var down func() error
		baseURL, down, err = probe.Up(ctx, probe.Compose{File: tf.compose, Service: tf.service, Port: tf.port})
		defer func() { err = withDown(err, down()) }()
		if err != nil {
			return report.Report{}, err
		}
	}
	cfg := in.cfg.Test
	return probe.Run(ctx, spec, probe.Options{
		BaseURL: baseURL, FailOn: in.failOn, RefRoot: in.refRoot,
		TokenA: os.Getenv(probe.EnvTokenA), TokenB: os.Getenv(probe.EnvTokenB),
		LoginA: cfg.Accounts.A.Login, LoginB: cfg.Accounts.B.Login,
		IDs: cfg.IDs, Skip: cfg.Skip, BaseSpec: tf.baseSpec,
	})
}

// errLeftRunning is a teardown that failed after the tests ran: the report
// is still printed, then the warning, and the exit code is 2.
var errLeftRunning = errors.New("the tests ran, but the environment was left running")

// withDown adds a failed teardown to a run's error: the user must hear the
// environment may still be up.
func withDown(err, downErr error) error {
	switch {
	case downErr == nil:
		return err
	case err == nil:
		return fmt.Errorf("%w: %w", errLeftRunning, downErr)
	}
	return errors.Join(err, fmt.Errorf("and the environment may be left running: %w", downErr))
}
