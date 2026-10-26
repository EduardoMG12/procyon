package probe

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/EduardoMG12/procyon/internal/loader"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/report"
)

// verdict is how one B check ended: a finding, a note saying why it could
// not tell, and the matrix cell either way.
type verdict struct {
	finding *report.Finding
	note    string
	cell    report.Cell
}

// cannotTell is a verdict with no finding: a note, and a skipped cell.
func cannotTell(note string) verdict {
	return verdict{note: note, cell: report.Cell{Outcome: report.Skipped}}
}

// otherAccount calls op as B with A's object in the path (f) and tells
// whether B reached it (PRC102): readAsB for a GET, writeAsB for anything
// else.
func (s *session) otherAccount(ctx context.Context, op loader.Operation, f filled) (verdict, error) {
	if op.Method == http.MethodGet {
		return s.readAsB(ctx, op, f)
	}
	return s.writeAsB(ctx, op, f)
}

// readAsB is reached when B's 2xx answer holds values A's answer for the
// same object also held, that B's own reads never showed and B's own
// object does not hold: A's data, not something every user sees.
func (s *session) readAsB(ctx context.Context, op loader.Operation, f filled) (verdict, error) {
	toA := s.ofA.bodies[f.path]
	if toA == nil {
		// Discovery read another object (A's own was not known yet): A
		// reads this one now, to compare with what B gets.
		exchange, body, err := s.sendFull(ctx, op, f.path, s.a)
		if err != nil || !success(exchange) {
			return cannotTell("not tested as B: A's own read of it failed"), err
		}
		s.ofA.bodies[f.path], toA = body, body
	}
	exchange, toB, err := s.sendFull(ctx, op, f.path, s.b)
	if err != nil || !success(exchange) {
		return verdict{cell: cellOf(exchange, false)}, err
	}
	shared := sharedUnseen(toB, toA, s.ofB.harvest, f.values)
	if len(shared) > 0 {
		if shared, err = s.withoutBsOwn(ctx, op, f.path, shared); err != nil {
			return verdict{}, err
		}
	}
	if len(shared) == 0 {
		return verdict{cell: cellOf(exchange, false)}, nil
	}
	return verdict{finding: bolaFinding(op, exchange, []report.Exchange{exchange}), cell: cellOf(exchange, true)}, nil
}

// withoutBsOwn drops the values B's own object on the same operation also
// holds ("active", a type, a year): they are not A's data. It only can when
// Procyon knows which object is B's (B's identity marks one).
func (s *session) withoutBsOwn(ctx context.Context, op loader.Operation, asked string, shared []string) ([]string, error) {
	own, err := s.ofB.fill(op.Path)
	if err != nil || !own.own || own.path == asked {
		return shared, nil
	}
	mine, body, err := s.sendFull(ctx, op, own.path, s.b)
	if err != nil || !success(mine) {
		return shared, err
	}
	inMine := valuesIn(body)
	return slices.DeleteFunc(shared, func(v string) bool { return slices.Contains(inMine, v) }), nil
}

// writeAsB is reached when A, reading the object before and after B's
// write or delete, sees it changed or gone. Without a GET on the same path,
// a write counts when its 2xx answer holds A's path values, and a delete
// cannot be told.
func (s *session) writeAsB(ctx context.Context, op loader.Operation, f filled) (verdict, error) {
	if op.NeedsBody && op.Body == nil {
		return cannotTell("not tested as B: it needs a request body and the spec gives no example"), nil
	}
	reader, canRead := s.readers[op.Path]
	if !canRead {
		if op.Method == http.MethodDelete {
			return cannotTell("not tested as B: without a GET on the same path, Procyon cannot tell whether a delete worked"), nil
		}
		return s.unreadableWrite(ctx, op, f)
	}

	if note, err := s.readBefore(ctx, op, reader, f.path); note != "" || err != nil {
		return cannotTell(note), err
	}
	exchange, _, err := s.sendFull(ctx, op, f.path, s.b)
	if err != nil || !success(exchange) {
		return verdict{cell: cellOf(exchange, false)}, err
	}
	after, afterBody, err := s.sendFull(ctx, reader, f.path, s.a)
	if err != nil {
		return verdict{}, err
	}
	var reached bool
	switch {
	case op.Method == http.MethodDelete && (after.Status == http.StatusNotFound || after.Status == http.StatusGone):
		reached = true // gone
	case op.Method == http.MethodDelete && !success(after):
		// A 429 or a 503 says nothing about the object.
		return cannotTell(fmt.Sprintf("not confirmed: after B's delete, A's read got %d", after.Status)), nil
	case op.Method == http.MethodDelete:
		reached = false // still there
	default:
		// Only the fields B sent count: a timestamp or a view counter
		// changes on every read. readBefore made sure they were not
		// there yet.
		reached = success(after) && hasAllValuesOf(afterBody, op.Body)
	}
	if !reached {
		return verdict{cell: cellOf(exchange, false)}, nil
	}
	return verdict{finding: bolaFinding(op, exchange, []report.Exchange{exchange, after}), cell: cellOf(exchange, true)}, nil
}

// readBefore is A's read of its object before B's write or delete. Its note
// says why the write could not be judged: A cannot read it, the read does
// not show what the write sets, or the object already holds it.
func (s *session) readBefore(ctx context.Context, op, reader loader.Operation, path string) (note string, err error) {
	exchange, body, err := s.sendFull(ctx, reader, path, s.a)
	switch {
	case err != nil || !success(exchange):
		return "not tested as B: A could not read the object first", err
	case op.Method == http.MethodDelete:
		return "", nil
	case !hasAnyFieldOf(body, op.Body):
		return "not tested as B: the GET on this path does not show the fields this write sets, so a change could not be seen", nil
	case hasAllValuesOf(body, op.Body):
		return "not tested as B: A's object already holds the request example's values, so a change could not be seen", nil
	}
	return "", nil
}

// unreadableWrite judges a write with no GET on the same path: only B's
// own answer can tell, when it holds A's path values. Otherwise a 2xx is a
// note, never a pass.
func (s *session) unreadableWrite(ctx context.Context, op loader.Operation, f filled) (verdict, error) {
	exchange, body, err := s.sendFull(ctx, op, f.path, s.b)
	if err != nil || !success(exchange) {
		return verdict{cell: cellOf(exchange, false)}, err
	}
	if mentionsAny(body, unseen(f.values, s.ofB.harvest)) {
		return verdict{finding: bolaFinding(op, exchange, []report.Exchange{exchange}), cell: cellOf(exchange, true)}, nil
	}
	return verdict{
		note: fmt.Sprintf("not confirmed: B got %d, and without a GET on the same path Procyon cannot tell whether "+
			"A's object changed", exchange.Status),
		cell: report.Cell{Outcome: report.Skipped, Status: exchange.Status},
	}, nil
}

// bolaFinding is a PRC102 finding: what B did to A's object, and the
// requests that prove it.
func bolaFinding(op loader.Operation, exchange report.Exchange, evidence []report.Exchange) *report.Finding {
	var what string
	switch op.Method {
	case http.MethodGet:
		what = "read"
	case http.MethodDelete:
		what = "delete"
	default:
		what = "change"
	}
	return &report.Finding{
		Rule:      lint.RuntimeRule("PRC102"),
		Location:  op.Location,
		Operation: op.Key(),
		Why: fmt.Sprintf("Test account B called this operation on an object of test account A and got %d: "+
			"any user can %s other users' objects by changing the ID in the path.", exchange.Status, what),
		Fix: "On the server, check that the object belongs to the caller (or that the caller may " + what +
			" it) before acting, and answer 404 otherwise.",
		Evidence: evidence,
	}
}

// sharedUnseen lists the values B's answer and A's answer both hold that
// B's own reads never showed: A's data. Values that prove nothing are left
// out: the path's own values (an API may echo the ID it was asked for), the
// words true and false, and anything shorter than minTelling ("ok", "1").
func sharedUnseen(toB, toA []byte, ofB *harvest, pathValues []string) []string {
	inA := valuesIn(toA)
	var shared []string
	for _, value := range valuesIn(toB) {
		telling := len(value) >= minTelling && value != "true" && value != "false" && !slices.Contains(pathValues, value)
		if telling && slices.Contains(inA, value) && !ofB.saw(value) && !slices.Contains(shared, value) {
			shared = append(shared, value)
		}
	}
	return shared
}

// unseen keeps the values B's own responses never showed.
func unseen(values []string, ofB *harvest) []string {
	var kept []string
	for _, v := range values {
		if !ofB.saw(v) {
			kept = append(kept, v)
		}
	}
	return kept
}
