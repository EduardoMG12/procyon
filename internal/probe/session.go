package probe

import (
	"context"
	"fmt"
	"net/http"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// session is one run's testing phase: what discovery found, and what is
// left for the malformed pass.
type session struct {
	*runner
	res      *results
	ofA, ofB *discovery
	a, b     caller
	changed  map[string]bool // nil: every operation is tested
	readers  map[string]loader.Operation
	// toBreak are the writes the malformed pass will send bad bodies to,
	// with their path filled with A's object.
	toBreak   []filledOp
	broken    bool // the malformed pass has run
	unchanged int
}

var skipped = report.Cell{Outcome: report.Skipped}

// skippedRow is the matrix row of an operation nobody called.
func skippedRow(key string) report.MatrixRow {
	return report.MatrixRow{Operation: key, A: skipped, B: skipped, Anonymous: skipped}
}

// testOperation tests one operation: anonymously (PRC101), then as B on
// A's object (PRC102), and queues a write for the malformed pass. Each ends
// as a row of the matrix.
func (s *session) testOperation(ctx context.Context, op loader.Operation) error {
	key := op.Key()
	row := report.MatrixRow{Operation: key, A: s.ofA.cells[key]}
	switch {
	case s.skip[key]:
		s.res.note(op.Location, key+" not called: listed under test.skip")
		s.res.matrix = append(s.res.matrix, skippedRow(key))
		return nil
	case s.changed != nil && !s.changed[key]:
		// Still read as A during discovery, to find IDs for the changed
		// operations; just not tested.
		s.unchanged++
		row.B, row.Anonymous = report.Cell{Outcome: report.Unchanged}, report.Cell{Outcome: report.Unchanged}
		s.res.matrix = append(s.res.matrix, row)
		return nil
	}
	f, err := s.ofA.fill(op.Path, op.Query)
	if err != nil {
		s.res.note(op.Location, fmt.Sprintf("%s not tested: %v in A's responses; declare one under test.ids in .procyon.yaml", key, err))
		s.res.matrix = append(s.res.matrix, skippedRow(key))
		return nil
	}
	if row.Anonymous, err = s.anonymous(ctx, op, f.path); err != nil {
		return err
	}
	s.queueMalformed(op, f.path)
	switch {
	case op.Method == http.MethodGet && row.Anonymous.Status >= 200 && row.Anonymous.Status < 300 && (len(f.values) > 0 || s.isList(op)):
		// The anonymous caller read this already: anyone may, so neither B
		// reaching A's object (PRC102) nor A's objects in B's list (PRC108)
		// is a finding. B is not called, and its cell says why.
		row.B = report.Cell{Outcome: report.Public}
	case s.isList(op): // a list or search: A's objects in B's own list (PRC108)
		if row.B, err = s.listLeak(ctx, op); err != nil {
			return err
		}
		if row.B.Outcome != report.Reached && len(f.values) > 0 {
			// Not a bulk leak, but it names an object (a filter B can set to
			// A's value): test it as a PRC102 too.
			if row.B, err = s.asB(ctx, op, f); err != nil {
				return err
			}
		}
	case len(f.values) > 0: // an object in the path: one of A's to reach (PRC102)
		if row.B, err = s.asB(ctx, op, f); err != nil {
			return err
		}
	}
	s.res.matrix = append(s.res.matrix, row)
	return nil
}

// anonymous calls op with no credentials. Only an operation the spec
// protects can be reached by mistake (PRC101); one it leaves open is
// PRC001's business. Whatever the call reached must not show personal
// data (PRC106). Public operations are not called.
func (s *session) anonymous(ctx context.Context, op loader.Operation, path string) (report.Cell, error) {
	if op.Public {
		return report.Cell{Outcome: report.Public}, nil
	}
	exchange, body, err := s.sendFull(ctx, op, path, anonymous)
	if err != nil {
		return report.Cell{}, err
	}
	var found []report.Finding
	if success(exchange) {
		personal := personalData(op, exchange, body)
		if len(personal) > 0 {
			exchange = personal[0].Evidence[0] // the personal values masked, for PRC101 too
		}
		if op.NeedsAuth {
			found = append(found, anonymousAccess(op, exchange))
		}
		found = append(found, personal...)
	}
	s.res.findings = append(s.res.findings, found...)
	return cellOf(exchange, len(found) > 0), nil
}

// asB tests B on A's object in the path (PRC102).
func (s *session) asB(ctx context.Context, op loader.Operation, f filled) (report.Cell, error) {
	if !f.own && s.ofB.sawAllFor(op.Path, f.values) {
		// Every user is shown these IDs (a public list of every book), and
		// nothing says which object is A's: B reaching it proves nothing.
		// Only an ID shown for this path's own parameters counts: B seeing
		// "4" as a menu item's ID is no reason to skip A's order 4.
		s.res.noteOn(op, "not tested as B: every user is shown this object's ID and nothing marks it as A's; "+
			"declare one of A's under test.ids in .procyon.yaml")
		return skipped, nil
	}
	v, err := s.otherAccount(ctx, op, f)
	if err != nil {
		return report.Cell{}, err
	}
	if v.finding != nil {
		s.res.findings = append(s.res.findings, *v.finding)
	}
	if v.note != "" {
		s.res.noteOn(op, v.note)
	}
	return v.cell, nil
}

// queueMalformed keeps a non-public write for the malformed pass, or notes
// why it cannot be sent malformed bodies.
func (s *session) queueMalformed(op loader.Operation, path string) {
	if op.Method == http.MethodGet || op.Method == http.MethodDelete || op.Public {
		return
	}
	switch {
	case op.Body != nil && s.broken:
		// The malformed pass runs once, before the deletes; inTestOrder
		// keeps every write ahead of it.
		s.res.noteOn(op, "malformed input not tested: it came after the malformed pass")
	case op.Body != nil:
		s.toBreak = append(s.toBreak, filledOp{op, path})
	case op.NeedsBody:
		s.res.noteOn(op, "malformed input not tested: it needs a request body and the spec gives no example")
	}
}

// malformedPass sends malformed bodies to the queued writes, as A
// (PRC103, PRC104). noAnswer is true when one got no answer at all: a body
// that hangs the server (a regular expression that backtracks) may keep it
// busy for minutes, so nothing more is sent.
func (s *session) malformedPass(ctx context.Context) (noAnswer bool, err error) {
	s.broken = true
	for i, f := range s.toBreak {
		bad, note, hung, err := s.malformed(ctx, f.op, f.path, s.a)
		if err != nil {
			return false, err
		}
		s.res.findings = append(s.res.findings, bad...)
		if note != "" {
			s.res.noteOn(f.op, note)
		}
		if hung {
			for _, rest := range s.toBreak[i+1:] {
				s.res.noteOn(rest.op, "malformed input not tested: the server stopped answering after an earlier malformed request")
			}
			return true, nil
		}
	}
	return false, nil
}

// skipAfterHang notes an operation left untested because the server
// stopped answering.
func (s *session) skipAfterHang(op loader.Operation) {
	key := op.Key()
	s.res.note(op.Location, key+" not tested: the server stopped answering after a malformed request")
	s.res.matrix = append(s.res.matrix, report.MatrixRow{Operation: key, A: s.ofA.cells[key], B: skipped, Anonymous: skipped})
}

// cellOf is the matrix cell of a call: a finding when reached, otherwise
// allowed, failed or denied by its status.
func cellOf(exchange report.Exchange, reached bool) report.Cell {
	switch {
	case reached:
		return report.Cell{Outcome: report.Reached, Status: exchange.Status}
	case success(exchange):
		return report.Cell{Outcome: report.Allowed, Status: exchange.Status}
	case exchange.Status >= 500:
		return report.Cell{Outcome: report.Failed, Status: exchange.Status}
	}
	return report.Cell{Outcome: report.Denied, Status: exchange.Status}
}

// filledOp is an operation with its path filled with A's values.
type filledOp struct {
	op   loader.Operation
	path string
}

// anonymousAccess is a PRC101 finding.
func anonymousAccess(op loader.Operation, exchange report.Exchange) report.Finding {
	return report.Finding{
		Rule:      lint.RuntimeRule("PRC101"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("A request with no credentials got %d: anyone who can reach the API can call this operation, "+
			"though the spec says it needs authentication.", exchange.Status),
		Fix: "Make the server answer 401 to requests without valid credentials on this operation. " +
			"If it is meant to be open, mark it x-procyon-public with the reason.",
		Evidence: []report.Exchange{exchange},
	}
}

func success(exchange report.Exchange) bool {
	return exchange.Status >= 200 && exchange.Status < 300
}
