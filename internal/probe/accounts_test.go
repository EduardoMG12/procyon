package probe

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/EduardoMG12/procyon/internal/loader"
)

func TestAuthorize(t *testing.T) {
	tests := []struct {
		cred *loader.Credential
		want func(*http.Request) string
		is   string
	}{
		{&loader.Credential{In: "header", Name: "Authorization", Prefix: "Bearer "},
			func(r *http.Request) string { return r.Header.Get("Authorization") }, "Bearer t0k3n"},
		{&loader.Credential{In: "header", Name: "X-API-Key"},
			func(r *http.Request) string { return r.Header.Get("X-API-Key") }, "t0k3n"},
		{&loader.Credential{In: "query", Name: "api_key"},
			func(r *http.Request) string { return r.URL.Query().Get("api_key") }, "t0k3n"},
		{&loader.Credential{In: "cookie", Name: "session"},
			func(r *http.Request) string { c, _ := r.Cookie("session"); return c.Value }, "t0k3n"},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "http://127.0.0.1/notes?limit=5", nil)
		authorize(req, tt.cred, "t0k3n")
		if got := tt.want(req); got != tt.is {
			t.Errorf("%s %s: got %q, want %q", tt.cred.In, tt.cred.Name, got, tt.is)
		}
	}
	// No credential, or the anonymous caller: the request is left alone.
	req, _ := http.NewRequest("GET", "http://127.0.0.1/notes", nil)
	authorize(req, nil, "t0k3n")
	authorize(req, &loader.Credential{In: "header", Name: "Authorization"}, "")
	if len(req.Header) != 0 {
		t.Errorf("headers = %v, want none", req.Header)
	}
}

func TestMask(t *testing.T) {
	got := mask(`{"echo":"a+b/c"} http://x/?k=a%2Bb%2Fc`, "a+b/c", "")
	if want := `{"echo":"****"} http://x/?k=****`; got != want {
		t.Errorf("mask = %q, want %q", got, want)
	}
}

// A token the API echoes JSON-escaped is masked too.
func TestMaskJSONEscapedTokens(t *testing.T) {
	token := "a/b<c>&d"
	for _, echoed := range []string{`"a\/b<c>&d"`, `"a/b\u003cc\u003e\u0026d"`} {
		if got := mask(echoed, token); strings.Contains(got, "a/b") || strings.Contains(got, "a\\/b") {
			t.Errorf("mask(%s) = %s, want the token hidden", echoed, got)
		}
	}
}

// An excerpt never ends in the middle of a character.
func TestExcerptCutsOnACharacterBoundary(t *testing.T) {
	r := &runner{}
	body := strings.Repeat("a", maxBody-1) + "é" // é takes two bytes: the cut falls inside it
	got := r.excerpt(body)
	if !utf8.ValidString(got) || len(got) != maxBody-1 {
		t.Errorf("excerpt is %d bytes, valid UTF-8 %v; want %d and valid", len(got), utf8.ValidString(got), maxBody-1)
	}
}
