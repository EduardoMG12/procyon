package probe

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

func logins(passwordA string) (*Login, *Login) {
	return &Login{Operation: "POST /login", Token: "/session/token",
			Body: map[string]any{"username": "alice", "password": passwordA}},
		&Login{Operation: "POST /login", Token: "/session/token",
			Body: map[string]any{"username": "bob", "password": "${PROCYON_TEST_BOB_PASSWORD}"}}
}

func TestLoginGivesTheSameFindingsAsTokens(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	srv := httptest.NewServer(vulnapi.New(false))
	defer srv.Close()
	a, b := logins("alice-password")
	rep, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, LoginA: a, LoginB: b})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rep.Findings {
		got = append(got, f.Rule.ID+" "+f.Operation)
		for _, e := range f.Evidence {
			if strings.Contains(e.URL+e.Body, vulnapi.TokenA) || strings.Contains(e.URL+e.Body, vulnapi.TokenB) {
				t.Errorf("a token from a login is in the evidence: %+v", e)
			}
		}
	}
	want := []string{"PRC101 GET /notes", "PRC103 POST /notes", "PRC104 POST /notes", "PRC102 GET /notes/{id}",
		"PRC102 PUT /notes/{id}", "PRC103 PUT /notes/{id}", "PRC104 PUT /notes/{id}", "PRC102 DELETE /notes/{id}",
		"PRC101 GET /notes/{id}/preview", "PRC108 GET /notes-search",
		"PRC102 GET /owner-notes", "PRC106 GET /shop", "PRC106 GET /shop", "PRC102 GET /orders/{orderId}", "PRC109 POST /reviews"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
}

func TestFailedLoginNamesTheAccount(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	srv := httptest.NewServer(vulnapi.New(false))
	defer srv.Close()
	a, b := logins("wrong")
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, LoginA: a, LoginB: b})
	if err == nil || !strings.Contains(err.Error(), "login of test account A: POST /login answered 401") {
		t.Errorf("err = %v, want the failed login of A", err)
	}
	a, _ = logins("alice-password")
	a.Token = "/token"
	_, err = Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, LoginA: a, LoginB: b})
	if err == nil || !strings.Contains(err.Error(), "no string at /token") {
		t.Errorf("err = %v, want the missing token named", err)
	}
}

func TestPointer(t *testing.T) {
	v, _ := decode([]byte(`{"a": {"b/c": [{"t": "x"}], "m~n": 1}}`))
	tests := map[string]any{"/a/b~1c/0/t": "x", "/a/b~1c/1": nil, "/a/x": nil, "a": nil}
	for ptr, want := range tests {
		if got := pointer(v, ptr); got != want {
			t.Errorf("pointer(%q) = %v, want %v", ptr, got, want)
		}
	}
	if got := pointer(v, "/a/m~0n"); got == nil {
		t.Error("pointer(/a/m~0n) = nil, want the number")
	}
}

func TestExpand(t *testing.T) {
	t.Setenv("PROCYON_TEST_PW", "s3cret")
	got, secrets, err := expand(map[string]any{"password": "${PROCYON_TEST_PW}", "literal": "pa$$w$rd", "n": uint64(3)})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["password"] != "s3cret" || m["literal"] != "pa$$w$rd" || m["n"] != uint64(3) || !slices.Equal(secrets, []string{"s3cret"}) {
		t.Errorf("expand = %v, secrets %q", got, secrets)
	}
	if _, _, err := expand("${PROCYON_TEST_UNSET_VAR}"); err == nil || err.Error() != "${PROCYON_TEST_UNSET_VAR} is not set" {
		t.Errorf("unset variable: err = %v", err)
	}
}

// A token in the environment wins: the wrong password is never tried.
func TestEnvTokenWinsOverALogin(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	srv := httptest.NewServer(vulnapi.New(true))
	defer srv.Close()
	a, b := logins("wrong")
	if _, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, LoginA: a, LoginB: b}); err != nil {
		t.Errorf("A from the environment, B from a login: %v", err)
	}
}

func TestLoginToAnAPIThatIsDownNamesTheAccount(t *testing.T) {
	t.Setenv("PROCYON_TEST_BOB_PASSWORD", "bob-password")
	a, b := logins("alice-password")
	_, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: "http://127.0.0.1:1", LoginA: a, LoginB: b})
	if err == nil || !strings.Contains(err.Error(), "login of test account A") {
		t.Errorf("err = %v, want it to name account A", err)
	}
}

// A login can read only PROCYON_* variables: the config sits next to the
// spec, where a pull request can change it.
func TestExpandReadsOnlyProcyonVariables(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-send")
	_, _, err := expand(map[string]any{"password": "${AWS_SECRET_ACCESS_KEY}"})
	if err == nil || !strings.Contains(err.Error(), "only variables named PROCYON_*") || strings.Contains(err.Error(), "do-not-send") {
		t.Errorf("err = %v, want the variable refused, never its value", err)
	}
}
