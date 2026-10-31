// Package vulnapi is a small notes API that is vulnerable on purpose, with a
// fixed twin. It is the acceptance test of `procyon test`: the vulnerable
// API must produce exactly the findings planted in it (see README.md), and
// the fixed one none.
//
// Never run it anywhere but a test or a disposable container.
package vulnapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// The two seeded test accounts and their bearer tokens.
const (
	TokenA = "token-alice"
	TokenB = "token-bob"
)

// maxTitle and maxBody are the spec's maxLength for a note's fields.
const (
	maxTitle = 100
	maxBody  = 10000
)

type note struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type server struct {
	fixed bool

	mu     sync.Mutex
	notes  map[string]*note
	nextID int
}

// New returns the API's handler. With fixed false, it has the planted
// vulnerabilities; with fixed true, none of them.
func New(fixed bool) http.Handler {
	s := &server{fixed: fixed, notes: map[string]*note{}}
	// Seeded data: alice owns notes 1 and 2, bob owns note 3.
	s.add("alice", "Groceries", "eggs, milk")
	s.add("alice", "Bank", "PIN reminder")
	s.add("bob", "Ideas", "a raccoon mascot")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /me", s.me)
	mux.HandleFunc("GET /notes", s.list)
	mux.HandleFunc("POST /notes", s.create)
	mux.HandleFunc("GET /notes/{id}", s.get)
	mux.HandleFunc("PUT /notes/{id}", s.update)
	mux.HandleFunc("DELETE /notes/{id}", s.delete)
	mux.HandleFunc("GET /owner-notes", s.ofOwner)
	return mux
}

// add stores a new note and returns it. The caller holds no lock.
func (s *server) add(owner, title, body string) *note {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	n := &note{ID: strconv.Itoa(s.nextID), Owner: owner, Title: title, Body: body}
	s.notes[n.ID] = n
	return n
}

// caller returns the user a request's bearer token belongs to, or "".
func caller(r *http.Request) string {
	switch strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") {
	case TokenA:
		return "alice"
	case TokenB:
		return "bob"
	}
	return ""
}

// passwords are the seeded accounts' passwords, for POST /login.
var passwords = map[string]string{"alice": "alice-password", "bob": "bob-password"}

// login trades a username and password for the account's token.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("want {username, password}"))
		return
	}
	if want, ok := passwords[in.Username]; !ok || in.Password != want {
		writeJSON(w, http.StatusUnauthorized, errorBody("wrong username or password"))
		return
	}
	token := map[string]string{"alice": TokenA, "bob": TokenB}[in.Username]
	writeJSON(w, http.StatusOK, map[string]any{"session": map[string]string{"token": token}})
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	user := caller(r)
	if user == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": user})
}

// list returns the caller's notes.
//
// Vulnerable (PRC101): an anonymous caller gets every note.
func (s *server) list(w http.ResponseWriter, r *http.Request) {
	user := caller(r)
	if user == "" && s.fixed {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.notesOf(user))
}

// notesOf returns owner's notes, or every note when owner is "", in ID
// order so responses are stable. The caller holds the lock.
func (s *server) notesOf(owner string) []*note {
	notes := []*note{}
	for i := 1; i <= s.nextID; i++ {
		n := s.notes[strconv.Itoa(i)]
		if n != nil && (owner == "" || n.Owner == owner) {
			notes = append(notes, n)
		}
	}
	return notes
}

// ofOwner returns the notes of the user the owner query parameter names.
//
// Vulnerable (PRC102): any authenticated caller gets anyone's notes.
func (s *server) ofOwner(w http.ResponseWriter, r *http.Request) {
	user, owner := caller(r), r.URL.Query().Get("owner")
	switch {
	case user == "":
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return
	case owner == "":
		writeJSON(w, http.StatusBadRequest, errorBody("the owner query parameter is required"))
		return
	case s.fixed && owner != user:
		writeJSON(w, http.StatusNotFound, errorBody("no such owner"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.notesOf(owner))
}

// create stores a note for the caller.
//
// Vulnerable (PRC103, PRC104): a body that is not a note gives a 500, and a
// title longer than the spec's maxLength is accepted.
func (s *server) create(w http.ResponseWriter, r *http.Request) {
	user := caller(r)
	if user == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return
	}
	in, ok := s.readNote(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, s.add(user, in.Title, in.Body))
}

// get returns one note.
//
// Vulnerable (PRC102): any authenticated caller gets any note.
func (s *server) get(w http.ResponseWriter, r *http.Request) {
	n, ok := s.find(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, n)
}

// update replaces a note's title and body.
//
// Vulnerable (PRC102): any authenticated caller can change any note.
func (s *server) update(w http.ResponseWriter, r *http.Request) {
	n, ok := s.find(w, r)
	if !ok {
		return
	}
	in, ok := s.readNote(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n.Title, n.Body = in.Title, in.Body
	writeJSON(w, http.StatusOK, n)
}

// delete removes a note.
//
// Vulnerable (PRC102): any authenticated caller can delete any note.
func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	n, ok := s.find(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.notes, n.ID)
	w.WriteHeader(http.StatusNoContent)
}

// find returns the note the path names, after checking the caller is
// authenticated and, in the fixed API, owns it. Otherwise it writes the
// error response and returns false.
func (s *server) find(w http.ResponseWriter, r *http.Request) (*note, bool) {
	user := caller(r)
	if user == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return nil, false
	}
	s.mu.Lock()
	n := s.notes[r.PathValue("id")]
	s.mu.Unlock()
	// The fixed API answers 404, not 403, for someone else's note: a 403
	// would confirm that the ID exists.
	if n == nil || (s.fixed && n.Owner != user) {
		writeJSON(w, http.StatusNotFound, errorBody("no such note"))
		return nil, false
	}
	return n, true
}

// readNote decodes a request body into a note's title and body. Otherwise it
// writes the error response and returns false.
func (s *server) readNote(w http.ResponseWriter, r *http.Request) (note, bool) {
	var in struct {
		Title *string `json:"title"`
		Body  string  `json:"body"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)
	switch {
	case err != nil && !s.fixed:
		// The planted bug: a decoding error is treated as the server's fault.
		writeJSON(w, http.StatusInternalServerError, errorBody("internal error"))
		return note{}, false
	case err != nil:
		writeJSON(w, http.StatusBadRequest, errorBody("the body is not a note: "+err.Error()))
		return note{}, false
	case s.fixed && (in.Title == nil || len(*in.Title) > maxTitle || len(in.Body) > maxBody):
		writeJSON(w, http.StatusBadRequest, errorBody("title is required, at most 100 characters; body at most 10000"))
		return note{}, false
	}
	var title string
	if in.Title != nil {
		title = *in.Title
	}
	return note{Title: title, Body: in.Body}, true
}

func errorBody(message string) map[string]string {
	return map[string]string{"error": message}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// An error here means the client went away; there is no one to tell.
	json.NewEncoder(w).Encode(v)
}
