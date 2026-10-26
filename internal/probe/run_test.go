package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EduardoMG12/procyon/internal/loader"

	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

const vulnapiSpec = "../vulnapi/openapi.yaml"

// runAgainst tests the notes API, vulnerable or fixed, and returns each
// finding as "rule operation".
func runAgainst(t *testing.T, fixed bool) (report.Report, []string) {
	t.Helper()
	rep := runOn(t, vulnapiSpec, vulnapi.New(fixed), Options{})
	got := findingKeys(rep)
	return rep, got
}

func TestRunFindsThePlantedVulnerabilities(t *testing.T) {
	rep, got := runAgainst(t, false)
	want := []string{
		"PRC101 GET /notes",
		"PRC103 POST /notes", "PRC104 POST /notes",
		"PRC102 GET /notes/{id}", "PRC102 PUT /notes/{id}", "PRC103 PUT /notes/{id}", "PRC104 PUT /notes/{id}",
		"PRC102 DELETE /notes/{id}",
	}
	if !slices.Equal(got, want) {
		t.Errorf("vulnerable API: findings %q, want %q", got, want)
	}
	if !rep.Failed {
		t.Error("a critical finding did not fail the run")
	}
	bola := rep.Findings[slices.Index(got, "PRC102 GET /notes/{id}")].Evidence
	if len(bola) != 1 || bola[0].Caller != "B" || !strings.HasSuffix(bola[0].URL, "/notes/1") ||
		strings.Contains(bola[0].URL+bola[0].Body, vulnapi.TokenB) {
		t.Errorf("PRC102 evidence = %+v, want B's GET /notes/1, with no token", bola)
	}
	evidence := rep.Findings[0].Evidence
	if len(evidence) != 1 || evidence[0].Caller != "anonymous" || evidence[0].Status != 200 ||
		!strings.HasSuffix(evidence[0].URL, "/notes") || !strings.Contains(evidence[0].Body, `"owner":"alice"`) {
		t.Errorf("evidence = %+v, want the anonymous GET /notes and its 200 with alice's notes", evidence)
	}
}

func TestRunFindsNothingInTheFixedTwin(t *testing.T) {
	rep, got := runAgainst(t, true)
	if len(got) != 0 || rep.Failed {
		t.Errorf("fixed API: findings %q, failed %v; want none", got, rep.Failed)
	}
	// A's GET /notes showed note IDs, so every operation on /notes/{id} was
	// called: the only note is that a plain http target has no TLS to check.
	if len(rep.Notes) != 1 || !strings.HasPrefix(rep.Notes[0].Message, "TLS not checked") {
		t.Errorf("notes = %v, want only the TLS one", rep.Notes)
	}
}

func TestRunRefusesAPublicTarget(t *testing.T) {
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://8.8.8.8", TokenA: "a", TokenB: "b"})
	if err == nil || !strings.Contains(err.Error(), "not a loopback or private address") {
		t.Errorf("err = %v, want the target refused", err)
	}
}

func TestInTestOrder(t *testing.T) {
	ops := []loader.Operation{
		{Method: "DELETE", Path: "/a"}, {Method: "GET", Path: "/a"}, {Method: "POST", Path: "/a"},
		{Method: "GET", Path: "/b"}, {Method: "PUT", Path: "/b"},
		{Method: "DELETE", Path: "/a/{id}"}, {Method: "DELETE", Path: "/a/{id}/notes/{noteId}"},
	}
	var got []string
	for _, op := range inTestOrder(ops) {
		got = append(got, op.Method+" "+op.Path)
	}
	want := []string{"GET /a", "GET /b", "POST /a", "PUT /b", "DELETE /a/{id}/notes/{noteId}", "DELETE /a/{id}", "DELETE /a"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %q, want %q", got, want)
	}
}

func TestRunNeedsBothAccounts(t *testing.T) {
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://127.0.0.1:1", TokenA: "a"})
	if err == nil || !strings.Contains(err.Error(), "PROCYON_USER_B_TOKEN") || strings.Contains(err.Error(), "PROCYON_USER_A_TOKEN") {
		t.Errorf("err = %v, want it to name PROCYON_USER_B_TOKEN only", err)
	}
}

// A 2xx to B is a pass when it does not hold A's object: B's own data, or
// nothing.
func TestPRC102NeedsAsObjectInTheResponse(t *testing.T) {
	for name, answer := range map[string]string{
		"B's own note": `{"id": "3", "owner": "bob"}`,
		"empty list":   `[]`,
		"not JSON":     `ok`,
	} {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Header.Get("Authorization")
				switch {
				case token == "":
					w.WriteHeader(http.StatusUnauthorized)
				case r.URL.Path == "/notes" && token == "Bearer "+vulnapi.TokenA:
					w.Write([]byte(`[{"id": "1", "owner": "alice"}]`))
				case r.URL.Path == "/notes":
					w.Write([]byte(`[{"id": "3", "owner": "bob"}]`))
				case token == "Bearer "+vulnapi.TokenB:
					w.Write([]byte(answer))
				}
			})
			for _, f := range findingsOf(runOn(t, vulnapiSpec, handler, Options{}), "PRC102") {
				t.Errorf("PRC102 on %s, want none", f.Operation)
			}
		})
	}
}

// A write that answers 2xx to B but leaves A's object as it was is a pass:
// A reads it before and after.
func TestPRC102WritesAreConfirmedByA(t *testing.T) {
	var sentByB []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if r.Method != "GET" && token == "Bearer "+vulnapi.TokenB {
			sentByB = append(sentByB, r.Method+" "+r.URL.Path)
		}
		switch {
		case token == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "GET" && r.URL.Path == "/notes" && token == "Bearer "+vulnapi.TokenB:
			w.Write([]byte(`[{"id": "3", "owner": "bob"}]`))
		case r.Method == "GET" && r.URL.Path == "/notes/3":
			w.Write([]byte(`{"id": "3", "owner": "bob"}`))
		case r.Method == "GET" && token == "Bearer "+vulnapi.TokenB:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET" && r.URL.Path == "/notes": // A's notes
			w.Write([]byte(`[{"id": "1", "owner": "alice"}]`))
		case r.Method == "GET": // A's note, never changed, but read at a new time on every read
			fmt.Fprintf(w, `{"id": "1", "owner": "alice", "title": "Groceries", "readAt": %d}`, time.Now().UnixNano())
		default: // B's PUT and DELETE say yes and do nothing
			w.WriteHeader(http.StatusOK)
		}
	})
	rep := runOn(t, vulnapiSpec, handler, Options{})
	for _, f := range findingsOf(rep, "PRC102") {
		t.Errorf("PRC102 on %s, want none: A's note never changed", f.Operation)
	}
	if want := []string{"PUT /notes/1", "DELETE /notes/1"}; !slices.Equal(sentByB, want) {
		t.Errorf("B sent %q, want %q", sentByB, want)
	}
}

// After B's delete, A's read failing for another reason (a rate limit, a
// server error) is not proof the object is gone.
func TestPRC102DeleteNeedsA404(t *testing.T) {
	deleted := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		switch {
		case token == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "DELETE":
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && deleted:
			w.WriteHeader(http.StatusTooManyRequests)
		case r.Method == "GET" && r.URL.Path == "/notes" && token == "Bearer "+vulnapi.TokenA:
			w.Write([]byte(`[{"id": "1"}]`))
		case r.Method == "GET" && token == "Bearer "+vulnapi.TokenA:
			w.Write([]byte(`{"id": "1"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rep := runOn(t, vulnapiSpec, handler, Options{})
	for _, f := range rep.Findings {
		if f.Operation == "DELETE /notes/{id}" {
			t.Errorf("PRC102 on DELETE after a 429, want a note")
		}
	}
	if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return strings.Contains(n.Message, "A's read got 429") }) {
		t.Errorf("notes = %v, want one saying A's read got 429", rep.Notes)
	}
}

// A token the API echoes across the excerpt's cut is still masked.
func TestEvidenceNeverHoldsPartOfAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", maxBody-10) + r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	target, err := checkTarget(context.Background(), srv.URL, lookupHost)
	if err != nil {
		t.Fatal(err)
	}
	token := "secret-token-value"
	r := &runner{client: newClient(time.Second, 10), target: target, tokens: []string{token}}
	op := loader.Operation{Method: "GET", Path: "/me", Credential: &loader.Credential{In: "header", Name: "Authorization", Prefix: "Bearer "}}
	exchange, err := r.send(context.Background(), op, "/me", caller{name: "A", token: token})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(exchange.Body, "secret") || strings.Contains(exchange.Body, "sec") {
		t.Errorf("evidence body ends %q, holding part of the token", exchange.Body[len(exchange.Body)-20:])
	}
}

func TestRunFillsTheAuthorizationMatrix(t *testing.T) {
	rep, _ := runAgainst(t, false)
	var got []string
	for _, row := range rep.Matrix {
		got = append(got, fmt.Sprintf("%s A=%s %d B=%s %d anon=%s %d", row.Operation,
			row.A.Outcome, row.A.Status, row.B.Outcome, row.B.Status, row.Anonymous.Outcome, row.Anonymous.Status))
	}
	want := []string{
		"GET /health A=allowed 200 B= 0 anon=public 0",
		"GET /me A=allowed 200 B= 0 anon=denied 401",
		"GET /notes A=allowed 200 B= 0 anon=finding 200",
		"GET /notes/{id} A=allowed 200 B=finding 200 anon=denied 401",
		"POST /login A= 0 B= 0 anon=public 0",
		"POST /notes A= 0 B= 0 anon=denied 401",
		"PUT /notes/{id} A= 0 B=finding 200 anon=denied 401",
		"DELETE /notes/{id} A= 0 B=finding 204 anon=denied 401",
	}
	if !slices.Equal(got, want) {
		t.Errorf("matrix:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A lax server stores an accepted malformed write, which can leave A's
// object holding the example; B's checks run first, so PRC102 is still
// found (the malformed pass runs after every write's B check).
func TestMalformedWritesNeverHidePRC102(t *testing.T) {
	rep := runOn(t, "../../testdata/specs/runtime-notes-title-only.yaml", vulnapi.New(false), Options{})
	if !slices.ContainsFunc(rep.Findings, func(f report.Finding) bool { return f.Rule.ID == "PRC102" && f.Operation == "PUT /notes/{id}" }) {
		t.Errorf("findings %v, want PRC102 on PUT /notes/{id}", rep.Findings)
	}
	// What was sent is in the evidence: each mutation tells itself apart.
	for _, f := range rep.Findings {
		if f.Rule.ID == "PRC104" {
			for _, e := range f.Evidence {
				if e.Sent == "" {
					t.Errorf("PRC104 evidence %+v has no request body", e)
				}
			}
		}
	}
}

// An https copy with httptest's self-signed certificate is tested like any
// other, and its modern TLS gives no PRC105.
func TestRunOverHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(vulnapi.New(true))
	defer srv.Close()
	rep, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, TokenB: vulnapi.TokenB})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || len(rep.Notes) != 0 {
		t.Errorf("findings %v, notes %v; want none", rep.Findings, rep.Notes)
	}
}

func TestRunWithABaseSpecTestsOnlyChangedOperations(t *testing.T) {
	rep := runOn(t, vulnapiSpec, vulnapi.New(false), Options{BaseSpec: "../../testdata/specs/runtime-notes-base.yaml"})
	got := findingKeys(rep)
	// GET /notes (PRC101), GET and DELETE /notes/{id} did not change.
	want := []string{"PRC103 POST /notes", "PRC104 POST /notes", "PRC102 PUT /notes/{id}", "PRC103 PUT /notes/{id}", "PRC104 PUT /notes/{id}"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
	skipped := 0
	for _, row := range rep.Matrix {
		if row.Anonymous.Outcome == report.Unchanged {
			skipped++
		}
	}
	if skipped != 5 || !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return strings.Contains(n.Message, "5 of 8 operations unchanged") }) {
		t.Errorf("skipped rows %d, notes %v; want 5 and the unchanged note", skipped, rep.Notes)
	}
}

// What the VAmPI benchmark taught: an operation the spec leaves open is not
// PRC101; IDs every user can list still lead to a PRC102 when B gets A's
// secret; a write Procyon cannot check is a note; a body that hangs the
// server is PRC103 and the run goes on; test.skip is never called.
func TestLessonsFromVAmPI(t *testing.T) {
	reset := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userOf(r)
		switch {
		case r.URL.Path == "/reset":
			reset = true
		case r.URL.Path == "/users":
			w.Write([]byte(`[{"username": "alice"}, {"username": "bob"}]`))
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/me":
			fmt.Fprintf(w, `{"username": %q}`, user)
		case r.URL.Path == "/books": // bob's first: A's book is found by A's username, not by order
			w.Write([]byte(`[{"title": "bobs-book", "user": "bob"}, {"title": "alices-book", "user": "alice"}]`))
		case strings.HasPrefix(r.URL.Path, "/books/"):
			title := strings.TrimPrefix(r.URL.Path, "/books/")
			fmt.Fprintf(w, `{"title": %q, "secret": "secret of %s"}`, title, title)
		case strings.HasSuffix(r.URL.Path, "/password"):
			var in struct{ Password string }
			if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.Password) > 50 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/comments":
			var in struct{ Text string }
			if r.ContentLength <= 1000 && json.NewDecoder(r.Body).Decode(&in) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.ContentLength > 1000 {
				time.Sleep(time.Second) // a regular expression that backtracks
			}
			w.WriteHeader(http.StatusCreated)
		}
	})
	rep := runOn(t, "../../testdata/specs/runtime-vampi-like.yaml", handler,
		Options{Timeout: 300 * time.Millisecond, Skip: []string{"GET /reset"}})
	got := findingKeys(rep)
	if want := []string{"PRC102 GET /books/{title}", "PRC103 POST /comments"}; !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
	if reset {
		t.Error("GET /reset was called, though listed in Skip")
	}
	for _, want := range []string{"PUT /users/{username}/password: not confirmed", "GET /reset not called"} {
		if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return strings.Contains(n.Message, want) }) {
			t.Errorf("no note %q in %v", want, rep.Notes)
		}
	}
}

// A secure API that answers B with B's own note whatever ID it asks for,
// or echoes the ID with an error: no PRC102, even with generic words in
// both notes and a view counter that changes on every read.
func TestNoPRC102OnObjectsEveryoneMayRead(t *testing.T) {
	for name, answer := range map[string]string{
		"B's own note, generic values in both": `{"id": "3", "owner": "bob", "status": "active", "kind": "draft"}`,
		"the asked ID echoed back":             `{"id": "%s", "error": "not yours"}`,
	} {
		t.Run(name, func(t *testing.T) {
			views := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user := userOf(r)
				id := strings.TrimPrefix(r.URL.Path, "/notes/")
				switch {
				case r.URL.Path == "/health":
					w.Write([]byte(`{}`))
				case user == "":
					w.WriteHeader(http.StatusUnauthorized)
				case r.URL.Path == "/me":
					fmt.Fprintf(w, `{"name": %q}`, user)
				case r.URL.Path == "/notes" && strings.Contains(answer, "%s") && user == "bob":
					w.Write([]byte(`[{"id": "3", "owner": "bob"}]`)) // A's IDs unseen by B: only the echo filter stops it
				case r.URL.Path == "/notes": // a shared list, with a counter in every item
					views++
					fmt.Fprintf(w, `[{"id": "3", "owner": "bob", "views": %d}, {"id": "1", "owner": "alice", "views": %d}]`, views*1000, views*1000+1)
				case r.Method == "GET" && user == "alice":
					fmt.Fprintf(w, `{"id": %q, "owner": "alice", "status": "active", "kind": "draft"}`, id)
				case r.Method == "GET":
					if strings.Contains(answer, "%s") {
						fmt.Fprintf(w, answer, id)
					} else {
						w.Write([]byte(answer))
					}
				default: // only the owner may change or delete
					w.WriteHeader(http.StatusNotFound)
				}
			})
			rep := runOn(t, vulnapiSpec, handler, Options{})
			for _, f := range findingsOf(rep, "PRC102") {
				t.Errorf("PRC102 on %s: %+v", f.Operation, f.Evidence)
			}
			// A's note was found by A's name in GET /me, not by order: B's
			// test ran on note 1.
			if !slices.ContainsFunc(rep.Matrix, func(row report.MatrixRow) bool {
				return row.Operation == "GET /notes/{id}" && row.B.Outcome == report.Allowed
			}) {
				t.Errorf("B was not tested on A's note: %+v", rep.Matrix)
			}
		})
	}
}

// A write that needs a body the spec gives no example for is never dropped
// silently: a note says why it was not tested.
func TestWriteWithoutAnExampleGetsANote(t *testing.T) {
	rep := runOn(t, "../../testdata/specs/runtime-notes-no-example.yaml", vulnapi.New(true), Options{})
	for _, want := range []string{
		"POST /notes: malformed input not tested: it needs a request body",
		"PUT /notes/{id}: not tested as B: it needs a request body",
	} {
		if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return strings.HasPrefix(n.Message, want) }) {
			t.Errorf("no note %q in %v", want, rep.Notes)
		}
	}
}
