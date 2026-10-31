package vulnapi

import "net/http"

// order is a shop order. Nothing in what it shows marks whose it is.
type order struct {
	ID      string `json:"id"`
	Owner   string `json:"-"`
	Item    string `json:"item"`
	Address string `json:"address"`
}

// The shop, never changed: a menu every signed-in user sees, and each
// user's orders. Their IDs overlap on purpose: menu item 1 is not order 1.
var (
	menuItems  = []map[string]string{{"id": "1", "name": "Lamp"}, {"id": "2", "name": "Desk"}}
	shopOrders = []order{
		{ID: "1", Owner: "alice", Item: "Lamp", Address: "12 Elm Street"},
		{ID: "2", Owner: "bob", Item: "Desk", Address: "34 Oak Avenue"},
	}
)

// menu lists what the shop sells, the same for every signed-in user.
func (s *server) menu(w http.ResponseWriter, r *http.Request) {
	if _, ok := authenticated(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, menuItems)
}

// listOrders returns the caller's orders.
func (s *server) listOrders(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticated(w, r)
	if !ok {
		return
	}
	mine := []order{}
	for _, o := range shopOrders {
		if o.Owner == user {
			mine = append(mine, o)
		}
	}
	writeJSON(w, http.StatusOK, mine)
}

// getOrder returns one order.
//
// Vulnerable (PRC102): any authenticated caller gets any order, though
// every user sees its ID on the menu.
func (s *server) getOrder(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticated(w, r)
	if !ok {
		return
	}
	for _, o := range shopOrders {
		if o.ID == r.PathValue("orderId") && (!s.fixed || o.Owner == user) {
			writeJSON(w, http.StatusOK, o)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, errorBody("no such order"))
}
