package probe

import "testing"

// An ID anyone could guess is a small number, or the id of two kinds of
// object in A's responses. The same object read in a list and alone, with
// more fields, is one kind; so are a thousand copies of it.
func TestGuessable(t *testing.T) {
	h := newHarvest(nil)
	h.add("/services", []byte(`[{"id": "MQ", "name": "Wash", "price": "30"}, {"id": "Mg", "name": "Wax", "price": "50"}]`))
	h.add("/cars", []byte(`[{"id": "MQ", "plate": "ABC1234", "model": "Gol"}, {"id": "c-9f2b", "plate": "XYZ9876", "model": "Uno"}]`))
	h.add("/cars/{id}", []byte(`{"id": "c-9f2b", "plate": "XYZ9876", "model": "Uno", "color": "red"}`))
	h.add("/owners", []byte(`[{"id": "u-7", "name": "Ana"}, {"id": "u-7", "name": "Ana"}, {"id": "u-7", "name": "Ana"}]`))
	tests := []struct {
		values, params []string
		param, why     string // param "" when nothing is guessable
	}{
		{[]string{"7"}, []string{"id"}, "id", "a small number"},
		{[]string{"0"}, []string{"id"}, "id", "a small number"},
		{[]string{"c-9f2b", "999999"}, []string{"carId", "orderId"}, "orderId", "a small number"},
		{[]string{"MQ"}, []string{"id"}, "id", "which is also the id of another kind of object, so it is counted, not random"},
		{[]string{"1000000"}, []string{"id"}, "", ""},
		{[]string{"-3"}, []string{"id"}, "", ""},
		{[]string{"c-9f2b"}, []string{"id"}, "", ""}, // a car, in the list and alone
		{[]string{"u-7"}, []string{"id"}, "", ""},    // one owner, three times
		{[]string{"Mg"}, []string{"id"}, "", ""},     // only a service
	}
	for _, tt := range tests {
		param, value, why, ok := h.guessable(filled{values: tt.values, params: tt.params})
		if param != tt.param || why != tt.why || ok != (tt.param != "") || (ok && value == "") {
			t.Errorf("guessable(%q) = %q, %q, %q, %v; want %q, %q", tt.values, param, value, why, ok, tt.param, tt.why)
		}
	}
}
