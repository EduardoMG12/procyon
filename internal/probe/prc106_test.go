package probe

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// PRC106 reports each place of an anonymous answer that holds personal
// data once, with every personal value masked in the evidence. The shop's
// own phone is ignored by field; the other fields of the same answer are
// still reported.
func TestPRC106PersonalDataInAnAnonymousAnswer(t *testing.T) {
	tests := []struct {
		name, answer string
		want         []string // the fields reported
		ignored      bool     // the shop's own phone, ignored by field
	}{
		{"personal fields",
			`{"phone": "+55 11 3333-4444", "reviews": [{"email": "ana@example.com", "cpf": "123.456.789-09"}, {"email": "bia@example.com"}]}`,
			[]string{"reviews.cpf", "reviews.email"}, true},
		{"none: no value, a placeholder, another name",
			`{"phone": null, "email": "n/a", "orderNumber": "11987654321", "supportEmail": "help@shop.example"}`,
			nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.answer))
			})
			rep := runOn(t, "../../testdata/specs/prc106.yaml", handler, Options{})
			var got []string
			for _, f := range findingsOf(rep, "PRC106") {
				got = append(got, f.Field)
				e := f.Evidence[0]
				for _, v := range []string{"+55 11 3333-4444", "ana@example.com", "123.456.789-09"} {
					if strings.Contains(e.Body, v) {
						t.Errorf("%s: evidence %q shows %q", f.Field, e.Body, v)
					}
				}
				if e.Caller != "anonymous" || !strings.Contains(e.Body, `"phone": "****"`) {
					t.Errorf("%s: evidence %+v, want the anonymous call with the values masked", f.Field, e)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("PRC106 on %q, want %q", got, tt.want)
			}
			ignored := len(rep.Ignored) == 1 && rep.Ignored[0].Finding.Field == "phone"
			if ignored != tt.ignored {
				t.Errorf("ignored %+v, want the shop's phone ignored: %v", rep.Ignored, tt.ignored)
			}
		})
	}
}

// An operation that needs a token and answers personal data without one is
// both PRC101 and PRC106, and neither finding shows the data.
func TestPRC106OnAProtectedOperation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name": "Ana", "email": "ana@example.com"}]`))
	})
	rep := runOn(t, "../../testdata/specs/prc106-protected.yaml", handler, Options{})
	if got := findingKeys(rep); !slices.Equal(got, []string{"PRC101 GET /customers", "PRC106 GET /customers"}) {
		t.Errorf("findings %q, want PRC101 and PRC106", got)
	}
	for _, f := range rep.Findings {
		if body := f.Evidence[0].Body; strings.Contains(body, "ana@example.com") {
			t.Errorf("%s evidence shows the e-mail: %s", f.Rule.ID, body)
		}
	}
}

// PRC106's fix suggests an ignore that works when followed: a field ignore
// when the response schema declares the field (an ignore may name no
// other), otherwise declaring it first.
func TestPRC106FixSuggestsAnIgnoreTheSpecAccepts(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"phone": "+55 11 3333-4444", "reviews": [{"email": "ana@example.com"}]}`))
	})
	rep := runOn(t, "../../testdata/specs/prc106.yaml", handler, Options{})
	fixes := map[string]string{}
	for _, f := range findingsOf(rep, "PRC106") {
		fixes[f.Field] = f.Fix
	}
	for _, ig := range rep.Ignored {
		fixes[ig.Finding.Field] = ig.Finding.Fix
	}
	declared, undeclared := fixes["phone"], fixes["reviews.email"]
	if !strings.Contains(declared, "field: phone") || strings.Contains(declared, "response schema") {
		t.Errorf("fix for phone, which the schema declares: %q, want only the field ignore", declared)
	}
	if !strings.Contains(undeclared, "declare reviews.email in the operation's response schema") ||
		!strings.Contains(undeclared, "field: reviews.email") {
		t.Errorf("fix for reviews.email, which the schema does not declare: %q, want both steps", undeclared)
	}
}
