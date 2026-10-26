package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/EduardoMG12/procyon/internal/loader"
)

func TestHarvestFillsPathParameters(t *testing.T) {
	h := newHarvest(map[string][]string{"report_id": {"r-9"}})
	h.add("/orders", []byte(`[{"id": 7, "customer": {"customerId": "c 1"}}, {"id": 8}]`))
	h.add("/me", []byte(`{"id": "u1", "teamId": "t1"}`))
	h.add("/broken", []byte(`not json`))
	h.add("/invoices", []byte(`[{"customer": {"id": "c9"}, "id": 1234567890123456789}]`))

	tests := []struct{ path, want, err string }{
		{"/orders/{id}", "/orders/7", ""},                    // the parent collection's id, in order
		{"/orders/{orderId}", "/orders/7", ""},               // a parent's id fills {orderId}
		{"/customers/{customer_id}", "/customers/c%201", ""}, // the same name anywhere; escaped
		{"/teams/{teamId}/members", "/teams/t1/members", ""},
		{"/reports/{reportId}", "/reports/r-9", ""},             // declared in .procyon.yaml
		{"/invoices/{id}", "/invoices/1234567890123456789", ""}, // its own id, not the nested customer's; no float rounding
		{"/payments/{paymentId}", "", "no value for {paymentId}"},
	}
	for _, tt := range tests {
		f, err := h.fill(tt.path)
		got := f.path
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("fill(%s) error = %v, want %q", tt.path, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("fill(%s) = %q, %v; want %q", tt.path, got, err, tt.want)
		}
	}
}

// discover calls a read as soon as an earlier response gave it a value,
// however the operations are ordered.
func TestDiscoverFollowsDependencies(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/projects":
			w.Write([]byte(`[{"id": "p1"}]`))
		case "/projects/p1":
			w.Write([]byte(`{"id": "p1", "ownerId": "u7"}`))
		}
	}))
	defer srv.Close()
	ops := []loader.Operation{ // a later read unlocks an earlier one
		{Method: "GET", Path: "/owners/{ownerId}"},
		{Method: "GET", Path: "/projects/{id}"},
		{Method: "GET", Path: "/projects"},
		{Method: "DELETE", Path: "/projects/{id}"}, // never called while discovering
	}
	target, err := checkTarget(context.Background(), srv.URL, lookupHost)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{client: newClient(0, 10), target: target}
	if _, err := r.discover(context.Background(), ops, caller{name: "A"}, newHarvest(nil), false); err != nil {
		t.Fatal(err)
	}
	want := []string{"/projects", "/projects/p1", "/owners/u7"}
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

// Two declared names that mean the same parameter give the same value on
// every run.
func TestDeclaredIDsAreDeterministic(t *testing.T) {
	for range 20 {
		h := newHarvest(map[string][]string{"order_id": {"a"}, "orderId": {"b"}})
		if f, _ := h.fill("/o/{orderId}"); f.path != "/o/b" {
			t.Fatalf("fill = %q, want /o/b (orderId sorts before order_id)", f.path)
		}
	}
}

// An object that holds one of A's identity values is A's own, wherever it
// is in the list.
func TestPickPrefersAsOwnObject(t *testing.T) {
	h := newHarvest(nil)
	h.add("/books", []byte(`[{"title": "bobs-book", "user": "bob"}, {"title": "alices-book", "user": "alice"}]`))
	f, err := h.fill("/books/{title}")
	if err != nil || f.path != "/books/bobs-book" || f.own {
		t.Errorf("without an identity: %+v, %v; want the first book, not known to be own", f, err)
	}
	h.identity = map[string]string{"alice": "/me"}
	if f, _ := h.fill("/books/{title}"); f.path != "/books/alices-book" || !f.own {
		t.Errorf("with A's identity: %+v; want alice's book, own", f)
	}
}
