package test

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
			Body: map[string]any{"username": "bob", "password": "${VULNAPI_BOB_PASSWORD}"}}
}

func TestLoginGivesTheSameFindingsAsTokens(t *testing.T) {
	t.Setenv("VULNAPI_BOB_PASSWORD", "bob-password")
	srv := httptest.NewServer(vulnapi.New(false))
	defer srv.Close()
	a, b := logins("alice-password")
	report, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, LoginA: a, LoginB: b})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range report.Findings {
		got = append(got, f.Rule.ID+" "+f.Operation)
		for _, e := range f.Evidence {
			if strings.Contains(e.URL+e.Body, vulnapi.TokenA) || strings.Contains(e.URL+e.Body, vulnapi.TokenB) {
				t.Errorf("a token from a login is in the evidence: %+v", e)
			}
		}
	}
	want := []string{"PRC101 GET /notes", "PRC102 GET /notes/{id}", "PRC102 PUT /notes/{id}", "PRC102 DELETE /notes/{id}"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
}

func TestFailedLoginNamesTheAccount(t *testing.T) {
	t.Setenv("VULNAPI_BOB_PASSWORD", "bob-password")
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
