package test

import (
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// Each kind of run applies the ignores of its own rules and never calls the
// other kind's unused.
func TestIgnoresOfLintAndRuntimeRulesStayApart(t *testing.T) {
	path := "../../testdata/specs/runtime-ignores.yaml"
	rep, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Ignored) != 1 || rep.Ignored[0].Finding.Rule.ID != "PRC001" || len(rep.Notes) != 0 {
		t.Errorf("lint: ignored %v, notes %v; want PRC001 ignored and no notes", rep.Ignored, rep.Notes)
	}

	spec, err := loader.Load(path, loader.Options{KnownRule: lint.KnownRule})
	if err != nil {
		t.Fatal(err)
	}
	op := spec.Operations()[0]
	finding := report.Finding{Rule: lint.RuntimeRule("PRC101"), Location: op.Location, Operation: op.Method + " " + op.Path}
	rep = finish(spec, []report.Finding{finding}, nil, 0)
	if len(rep.Findings) != 0 || len(rep.Ignored) != 1 || len(rep.Notes) != 0 || rep.Failed {
		t.Errorf("runtime: findings %v, ignored %v, notes %v, failed %v; want PRC101 ignored, no notes, not failed",
			rep.Findings, rep.Ignored, rep.Notes, rep.Failed)
	}

	rep = finish(spec, []report.Finding{{Rule: lint.RuntimeRule("PRC101"), Operation: "GET /other"}}, nil, 0)
	if len(rep.Findings) != 1 || !rep.Failed {
		t.Errorf("an unignored critical finding: findings %v, failed %v; want it kept and the run failed", rep.Findings, rep.Failed)
	}
}

// A runtime finding about no operation (PRC105) is covered by an ignore at
// the spec's root.
func TestRootIgnoreCoversARuntimeFindingAboutTheSpec(t *testing.T) {
	spec, err := loader.Load("../../testdata/specs/runtime-root-ignore.yaml", loader.Options{KnownRule: lint.KnownRule})
	if err != nil {
		t.Fatal(err)
	}
	rep := finish(spec, []report.Finding{{Rule: lint.RuntimeRule("PRC105"), Location: report.Location{Line: 1, Column: 1}}}, nil, 0)
	if len(rep.Findings) != 0 || len(rep.Ignored) != 1 {
		t.Errorf("findings %v, ignored %v; want PRC105 ignored", rep.Findings, rep.Ignored)
	}
}
