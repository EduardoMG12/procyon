package vulnapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The two seeded test accounts and their bearer tokens.
const (
	TokenA = "token-alice"
	TokenB = "token-bob"
)

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

// authenticated returns the user a request comes from. When its token is
// missing or unknown, it answers 401 and returns false.
func authenticated(w http.ResponseWriter, r *http.Request) (user string, ok bool) {
	if user = caller(r); user == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing or unknown token"))
		return "", false
	}
	return user, true
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

// me returns the caller's name.
func (s *server) me(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticated(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": user})
}
