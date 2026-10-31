package probe

import (
	"net/http"
	"testing"

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
