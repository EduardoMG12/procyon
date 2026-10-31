package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EduardoMG12/procyon/internal/report"
	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

// Each test here guards one decision of the oracle: removing the code it
// names makes it fail.

// markedAsB: when A's only note is the one it created from the example, B
// must write something else, or A's note "already holds" what B sent and
// the overwrite is never seen.
func TestBWritesSomethingAsObjectDoesNotHold(t *testing.T) {
	var mu sync.Mutex
	notes := map[string]map[string]string{} // id → fields
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userOf(r)
		mu.Lock()
		defer mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/notes/")
		switch {
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "POST":
			id = fmt.Sprint(len(notes) + 1)
			notes[id] = map[string]string{"owner": user, "title": "Shopping list", "body": "bread, coffee"}
			fmt.Fprintf(w, `{"id": %q, "owner": %q}`, id, user)
		case r.URL.Path == "/notes":
			var mine []string
			for nid, n := range notes {
				if n["owner"] == user {
					mine = append(mine, fmt.Sprintf(`{"id": %q, "owner": %q}`, nid, user))
				}
			}
			fmt.Fprintf(w, "[%s]", strings.Join(mine, ","))
		case notes[id] == nil:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "PUT": // anyone changes any note: the BOLA
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			for k, v := range in {
				notes[id][k] = v
			}
			fmt.Fprintf(w, `{"id": %q}`, id)
		case r.Method == "GET":
			n := notes[id]
			fmt.Fprintf(w, `{"id": %q, "owner": %q, "title": %q, "body": %q}`, id, n["owner"], n["title"], n["body"])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rep := runOn(t, vulnapiSpec, handler, Options{})
	if !slices.Contains(findingKeys(rep), "PRC102 PUT /notes/{id}") {
		t.Errorf("findings %q, want PRC102 on PUT /notes/{id}", findingKeys(rep))
	}
}

// saw: a value B's own reads show (its tenant, shared with A) is not A's
// data, even when nothing marks whose object is whose.
func TestValuesBSawAreNotAsData(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userOf(r)
		switch {
		case user == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/notes" && user == "alice":
			w.Write([]byte(`[{"id": "1", "tenant": "acme-corp"}]`))
		case r.URL.Path == "/notes":
			w.Write([]byte(`[{"id": "3", "tenant": "acme-corp"}]`))
		case r.Method == "GET" && user == "alice":
			w.Write([]byte(`{"id": "1", "tenant": "acme-corp", "title": "Groceries"}`))
		case r.Method == "GET":
			w.Write([]byte(`{"tenant": "acme-corp"}`)) // B sees only its own tenant: safe
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rep := runOn(t, vulnapiSpec, handler, Options{})
	for _, f := range findingsOf(rep, "PRC102") {
		t.Errorf("PRC102 on %s, want none: B saw only its own tenant", f.Operation)
	}
}

// The control request: an operation whose example already fails (404) gets
// a note, not silence.
func TestMalformedNotesAFailingExample(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case userOf(r) == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "POST":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Write([]byte(`[]`))
		}
	})
	rep := runOn(t, vulnapiSpec, handler, Options{})
	if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool {
		return strings.Contains(n.Message, "POST /notes: malformed input not tested: the spec's own example, sent as A, already gets 404")
	}) {
		t.Errorf("notes %v, want the failing example noted", rep.Notes)
	}
}

// A list stays a list for identity marks, even after a created object is
// recorded under its path.
func TestACreatedObjectDoesNotMakeAListSingle(t *testing.T) {
	h := newHarvest(nil)
	h.add("/notes", []byte(`[{"id": "1"}]`))
	h.add("/notes", []byte(`{"id": "4"}`))
	if h.single["/notes"] {
		t.Error("/notes became a single-object path")
	}
}

// Short and generic values never count as A's data: "ok", "1".
func TestShortValuesAreNotTelling(t *testing.T) {
	toA := []byte(`{"id": "1", "status": "ok", "n": 7}`)
	toB := []byte(`{"status": "ok", "n": 7}`)
	if got := sharedUnseen(toB, toA, newHarvest(nil), nil); len(got) != 0 {
		t.Errorf("sharedUnseen = %q, want nothing", got)
	}
}

// mutations: a very long string is sent where the spec sets no maxLength,
// to find a crash or a hang (PRC103), but the spec allows it: a server
// that accepts it is no PRC104 (VAmPI's register and login).
func TestAnUnboundedLongStringAcceptedIsNoPRC104(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /comments:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                text: {type: string}
            example: {text: hello}
      responses: {"201": {description: created}}
`)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Text string }
		switch {
		case userOf(r) == "":
			w.WriteHeader(http.StatusUnauthorized)
		case json.NewDecoder(r.Body).Decode(&in) != nil: // text as a number
			w.WriteHeader(http.StatusBadRequest)
		default: // any length, as the spec allows
			w.WriteHeader(http.StatusCreated)
		}
	})
	rep := runOn(t, spec, handler, Options{})
	if got := findingKeys(rep); len(got) != 0 {
		t.Errorf("findings %q, want none: the spec sets no maxLength", got)
	}
}

// testInOrder: once a malformed body gets no answer, the deletes that come
// after the malformed pass are noted, never sent.
func TestNoDeleteIsSentAfterTheServerHangs(t *testing.T) {
	api := vulnapi.New(false)
	var mu sync.Mutex
	deleted := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"title":42`)) {
			time.Sleep(time.Second) // the title-as-a-number mutation hangs the server
			return
		}
		mu.Lock()
		deleted = deleted || r.Method == http.MethodDelete
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		api.ServeHTTP(w, r)
	})
	rep := runOn(t, vulnapiSpec, handler, Options{Timeout: 300 * time.Millisecond})
	if deleted {
		t.Error("a DELETE was sent after the server stopped answering")
	}
	want := "DELETE /notes/{id} not tested: the server stopped answering after a malformed request"
	if !slices.ContainsFunc(rep.Notes, func(n report.Note) bool { return n.Message == want }) {
		t.Errorf("no note %q in %v", want, rep.Notes)
	}
}
