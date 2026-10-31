package probe

import (
	"fmt"
	"slices"
	"testing"
)

// A value is personal data when both its field's name and its shape say
// so, at any depth of the answer, in a list or not.
func TestPersonalValues(t *testing.T) {
	tests := []struct {
		name, answer string
		want         []string // "place: kind value", in the answer's order
	}{
		{"nested, and in a list",
			`{"phone": "+55 11 3333-4444", "reviews": [{"email": "ana@example.com", "cpf": "123.456.789-09"}, {"email": "bia@example.com"}]}`,
			[]string{
				"phone: a phone number +55 11 3333-4444",
				"reviews.cpf: a national ID 123.456.789-09", "reviews.email: an e-mail address ana@example.com",
				"reviews.email: an e-mail address bia@example.com",
			}},
		{"numbers, an ID with a check letter, a list of texts",
			`[{"celular": 11987654321, "ssn": "078-05-1120", "rg": "12.345.678-X", "emails": ["ana@example.com"]}]`,
			[]string{
				"celular: a phone number 11987654321", "emails: an e-mail address ana@example.com",
				"rg: a national ID 12.345.678-X", "ssn: a national ID 078-05-1120",
			}},
		{"no value, or not that kind's shape",
			`{"phone": null, "email": "", "cpf": "n/a", "reviews": [{"email": "not an e-mail", "telefone": "ligue para a loja", "passport": "3f2a9c1e-0d4b-4c7a-9e21-5b8f6a7d0c3e"}]}`,
			nil},
		{"a personal shape under another name",
			`{"orderNumber": "11987654321", "supportEmail": "help@shop.example", "trackingCode": "123.456.789-09", "emailVerified": true}`,
			nil},
		{"not JSON", `ana@example.com`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, p := range personalValues([]byte(tt.answer)) {
				got = append(got, fmt.Sprintf("%s: %s %s", p.place, p.kind, p.value))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("personal values:\n%q\nwant:\n%q", got, tt.want)
			}
		})
	}
}
