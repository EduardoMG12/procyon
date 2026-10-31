package vulnapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests pin the planted vulnerabilities, so `procyon test`'s own
// acceptance tests rest on a known API: each request below is answered one
// way by the vulnerable API and another way by the fixed twin.
func TestPlantedVulnerabilities(t *testing.T) {
	tests := []struct {
		name              string
		method, path      string
		token             string
		body              string
		vulnerable, fixed int
	}{
		{"health is public", "GET", "/health", "", "", 200, 200},
		{"me needs a token", "GET", "/me", "", "", 401, 401},
		{"PRC101: anonymous list", "GET", "/notes", "", "", 200, 401},
		{"owner reads own note", "GET", "/notes/1", TokenA, "", 200, 200},
		{"PRC102: B reads A's note", "GET", "/notes/1", TokenB, "", 200, 404},
		{"PRC102: B changes A's note", "PUT", "/notes/1", TokenB, `{"title":"pwned"}`, 200, 404},
		{"PRC102: B deletes A's note", "DELETE", "/notes/2", TokenB, "", 204, 404},
		{"owner lists own notes", "GET", "/owner-notes?owner=alice", TokenA, "", 200, 200},
		{"PRC102: B lists A's notes", "GET", "/owner-notes?owner=alice", TokenB, "", 200, 404},
		{"the owner is required", "GET", "/owner-notes", TokenA, "", 400, 400},
		{"every user sees the menu", "GET", "/menu", TokenB, "", 200, 200},
		{"anyone sees the shop's page", "GET", "/shop", "", "", 200, 200},
		{"owner reads own order", "GET", "/orders/1", TokenA, "", 200, 200},
		{"PRC102: B reads A's order", "GET", "/orders/1", TokenB, "", 200, 404},
		{"anonymous read is refused", "GET", "/notes/1", "", "", 401, 401},
		{"PRC103: wrong type", "POST", "/notes", TokenA, `{"title":42}`, 500, 400},
		{"PRC104: missing title", "POST", "/notes", TokenA, `{"body":"x"}`, 201, 400},
		{"PRC104: title too long", "POST", "/notes", TokenA, `{"title":"` + strings.Repeat("a", 101) + `"}`, 201, 400},
		{"valid note", "POST", "/notes", TokenA, `{"title":"ok"}`, 201, 201},
	}
	for _, fixed := range []bool{false, true} {
		for _, tt := range tests {
			want := tt.vulnerable
			if fixed {
				want = tt.fixed
			}
			// A fresh API per request, so a delete never changes another row.
			srv := httptest.NewServer(New(fixed))
			req, err := http.NewRequest(tt.method, srv.URL+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			srv.Close()
			if resp.StatusCode != want {
				t.Errorf("fixed=%v %s: %s %s = %d, want %d", fixed, tt.name, tt.method, tt.path, resp.StatusCode, want)
			}
		}
	}
}

// The shop's page shows its reviewer's e-mail only in the vulnerable API
// (PRC106).
func TestShopPageShowsTheReviewersContact(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		srv := httptest.NewServer(New(fixed))
		resp, err := http.Get(srv.URL + "/shop")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if shown := strings.Contains(string(body), "alice@example.com"); shown == fixed {
			t.Errorf("fixed=%v: GET /shop = %s, e-mail shown %v", fixed, body, shown)
		}
	}
}

// The fixed API lists only the caller's notes; this is what lets PRC102's
// oracle tell "B got its own data" from "B got A's".
func TestListIsTheCallersOwn(t *testing.T) {
	srv := httptest.NewServer(New(true))
	defer srv.Close()
	req, err := http.NewRequest("GET", srv.URL+"/notes", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+TokenB)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"alice"`) || !strings.Contains(string(body), `"bob"`) {
		t.Errorf("bob's list = %s, want only bob's notes", body)
	}
}
