package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

const loginsSpec = "../../testdata/specs/runtime-logins.yaml"

// formLogin signs in the way FastAPI's OAuth2 form does: a form in, the
// token in the JSON answer.
func formLogin(user, password string) *Login {
	return &Login{Operation: "POST /token", Form: map[string]string{"username": user, "password": password}, Token: "/access_token"}
}

// cookieLogin signs in with JSON, and the token comes back as a cookie.
func cookieLogin(user, password string) *Login {
	return &Login{Operation: "POST /session", Body: map[string]any{"username": user, "password": password}, Cookie: "sid"}
}

// loginsAPI is vulnapi behind the two logins of runtime-logins.yaml, with
// the session in the sid cookie instead of a bearer header.
func loginsAPI() http.Handler {
	api := vulnapi.New(false)
	// tokenOf signs in through vulnapi's own POST /login; "" when refused.
	tokenOf := func(user, password string) string {
		in, _ := json.Marshal(map[string]string{"username": user, "password": password})
		answer := httptest.NewRecorder()
		api.ServeHTTP(answer, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(in)))
		var out struct{ Session struct{ Token string } }
		json.Unmarshal(answer.Body.Bytes(), &out)
		return out.Session.Token
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			token := ""
			if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
				token = tokenOf(r.PostFormValue("username"), r.PostFormValue("password"))
			}
			if token == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, `{"access_token": %q, "token_type": "bearer"}`, token)
		case "/session":
			var in struct{ Username, Password string }
			json.NewDecoder(r.Body).Decode(&in)
			token := tokenOf(in.Username, in.Password)
			if token == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			if session, err := r.Cookie("sid"); err == nil {
				r.Header.Set("Authorization", "Bearer "+session.Value)
			}
			api.ServeHTTP(w, r)
		}
	})
}

// Each account signs in its own way, and the session goes where the spec's
// security scheme says: the sid cookie.
func TestLoginWithAFormOrACookie(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	rep := runOn(t, loginsSpec, loginsAPI(), Options{
		LoginA: formLogin("alice", "alice-password"),
		LoginB: cookieLogin("bob", "${PROCYON_TEST_BOB_PASSWORD}"),
	})
	want := report.MatrixRow{Operation: "GET /me", A: report.Cell{Outcome: report.Allowed, Status: 200},
		Anonymous: report.Cell{Outcome: report.Denied, Status: 401}}
	if !slices.Contains(rep.Matrix, want) {
		t.Errorf("matrix %+v; want the row %+v", rep.Matrix, want)
	}
	// B's login answered 303: it is no call of the run's to warn about.
	for _, n := range rep.Notes {
		if strings.Contains(n.Message, "redirect") {
			t.Errorf("note %q", n.Message)
		}
	}
}

func TestCookieLoginWithoutTheCookieNamesIt(t *testing.T) {
	srv := httptest.NewServer(loginsAPI())
	defer srv.Close()
	a := cookieLogin("alice", "alice-password")
	a.Cookie = "session"
	_, err := Run(context.Background(), loginsSpec, Options{BaseURL: srv.URL, LoginA: a, TokenB: vulnapi.TokenB})
	if want := "login of test account A: POST /session answered 303 with no cookie session"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

// A login that cannot work is refused with what is wrong, naming the
// account.
func TestLoginRefusalsSayWhy(t *testing.T) {
	srv := httptest.NewServer(loginsAPI())
	defer srv.Close()
	alice := map[string]any{"username": "alice", "password": "alice-password"}
	tests := []struct {
		spec  string
		login Login
		want  string
	}{
		{loginsSpec, Login{Operation: "POST /nowhere", Token: "/token"}, `the spec has no operation "POST /nowhere"`},
		{vulnapiSpec, Login{Operation: "GET /notes/{id}", Token: "/token"},
			"GET /notes/{id} needs a value in its path; use a login operation without one"},
		{loginsSpec, Login{Operation: "get /me", Body: alice, Token: "/token"}, "get /me is a GET, which sends no body"},
		// POST /session answers with a cookie and a redirect, not JSON.
		{loginsSpec, Login{Operation: "POST /session", Body: alice, Token: "/token"},
			"POST /session answered 303: redirects are not followed, and the token must be in the JSON answer"},
	}
	for _, tt := range tests {
		_, err := Run(context.Background(), tt.spec, Options{BaseURL: srv.URL, LoginA: &tt.login, TokenB: vulnapi.TokenB})
		if want := "login of test account A: " + tt.want; err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", tt.login.Operation, err, want)
		}
	}
}

// A token read from a cookie, and a password sent in a form, are masked in
// evidence like any other token, even when the API echoes them.
func TestCookieTokenAndFormPasswordAreMasked(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	api := loginsAPI()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			sent, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%s %s", r.Header.Get("Cookie"), sent)
			return
		}
		api.ServeHTTP(w, r)
	}))
	defer srv.Close()
	spec, err := loader.Load(loginsSpec, loader.Options{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := checkTarget(context.Background(), srv.URL, lookupHost)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{client: newClient(time.Second, 10), target: target}
	a, _, err := r.signIn(context.Background(), spec, Options{
		LoginA: cookieLogin("alice", "alice-password"),
		LoginB: formLogin("bob", "${PROCYON_TEST_BOB_PASSWORD}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := loader.Operation{Method: http.MethodPost, Path: "/echo", Credential: &loader.Credential{In: "cookie", Name: "sid"},
		Body: []byte("password=bob-password")}
	exchange, err := r.send(context.Background(), echo, "/echo", a)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sid=**** password=****"; exchange.Body != want || strings.Contains(exchange.Sent, "bob-password") {
		t.Errorf("evidence body %q, sent %q; want %q and the password masked", exchange.Body, exchange.Sent, want)
	}
}
