package probe

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// PRC108 is reported only for an object of A's in B's list: an item that
// holds a value only A's own reads showed, and that A's answer to the same
// list showed too. A short number in some other field of B's own item, or
// A's phone number copied into B's own order, is not A's object.
func TestPRC108NeedsAnObjectOfA(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /me:
    get:
      responses: {"200": {description: ok}}
  /vehicles:
    get:
      responses: {"200": {description: ok}}
  /orders:
    get:
      responses: {"200": {description: ok}}
  /orders/{orderId}:
    get:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`)
	me := map[string]string{
		"alice": `{"id": 2, "email": "alice@example.com", "phone": "5550001"}`,
		"bob":   `{"id": 3, "email": "bob@example.com", "phone": "5550002"}`,
	}
	// Each list is scoped to the caller. crAPI: bob's car model has id 2,
	// alice's user id. RESTaurant: bob's order went to alice's phone.
	vehicles := map[string]string{
		"alice": `[{"id": 5, "vin": "VIN-ALICE-0005", "model": {"id": 1, "name": "Corolla"}}]`,
		"bob":   `[{"id": 7, "vin": "VIN-BOB-0007", "model": {"id": 2, "name": "Aventador"}}]`,
	}
	orders := map[string]string{
		"alice": `[{"id": 4, "phone": "5550001", "dish": "alice's soup"}]`,
		"bob":   `[{"id": 6, "phone": "5550001", "dish": "bob's pie"}]`,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := userOf(r)
		switch {
		case who == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/me":
			w.Write([]byte(me[who]))
		case r.URL.Path == "/vehicles":
			w.Write([]byte(vehicles[who]))
		case r.URL.Path == "/orders":
			w.Write([]byte(orders[who]))
		case r.URL.Path == "/orders/4": // vulnerable: any account reads alice's order
			w.Write([]byte(`{"id": 4, "phone": "5550001", "dish": "alice's soup"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rep := runOn(t, spec, handler, Options{})
	got := findingKeys(rep)
	if want := []string{"PRC102 GET /orders/{orderId}"}; !slices.Equal(got, want) {
		t.Errorf("findings %q, want %q", got, want)
	}
}

// A leaking list is still reported, and the finding says which of A's
// values B's answer held, in which item and where A's reads showed it.
func TestPRC108NamesTheValueOfA(t *testing.T) {
	spec := writeSpec(t, bearerSpec+`  /me:
    get:
      responses: {"200": {description: ok}}
  /notes:
    get:
      responses: {"200": {description: ok}}
`)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := userOf(r)
		switch {
		case who == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/me":
			fmt.Fprintf(w, `{"id": %q, "username": %q}`, who[:1], who)
		case r.URL.Path == "/notes": // every account's notes
			w.Write([]byte(`[{"id": "n1", "owner": "alice"}, {"id": "n2", "owner": "bob"}]`))
		}
	})
	rep := runOn(t, spec, handler, Options{})
	found := findingsOf(rep, "PRC108")
	if len(found) != 1 {
		t.Fatalf("PRC108 findings %q, want one on GET /notes", findingKeys(rep))
	}
	for _, want := range []string{`"alice"`, `item with id "n1"`, "/me"} {
		if !strings.Contains(found[0].Why, want) {
			t.Errorf("why %q does not say %s", found[0].Why, want)
		}
	}
}
