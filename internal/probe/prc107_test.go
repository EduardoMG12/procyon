package probe

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
)

// PRC107 reports a public operation reached by an ID anyone could guess:
// a small number, or the id A also saw for another kind of object. The car
// read alone has more fields than in the list: the same kind. An operation
// that needs a login (the car's owner) is PRC101's and PRC102's, never
// PRC107's, though it answers anyone here.
func TestPRC107PredictableIDOnAPublicOperation(t *testing.T) {
	tests := []struct {
		name, service, car string
		want               []string
	}{
		{"a small number", "s-1", "7", []string{"GET /cars/{id}"}},
		{"a service's and a car's id are the same", "MQ", "MQ", []string{"GET /cars/{id}"}},
		{"random ids", "c2VydmljZQ", "MQ", nil},
		{"a large number", "s-1", "1234567", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/services":
					fmt.Fprintf(w, `[{"id": %q, "name": "Wash", "price": "30"}]`, tt.service)
				case "/cars":
					fmt.Fprintf(w, `[{"id": %q, "plate": "ABC1234", "model": "Gol"}]`, tt.car)
				case "/cars/" + tt.car:
					fmt.Fprintf(w, `{"id": %q, "plate": "ABC1234", "model": "Gol", "color": "red"}`, tt.car)
				case "/cars/" + tt.car + "/owner":
					w.Write([]byte(`{"name": "Ana"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			var got []string
			for _, f := range findingsOf(runOn(t, "../../testdata/specs/prc107.yaml", handler, Options{}), "PRC107") {
				got = append(got, f.Operation)
				if e := f.Evidence[0]; e.Caller != "anonymous" || e.URL != "/cars/"+tt.car {
					t.Errorf("evidence %+v, want the anonymous GET /cars/%s", e, tt.car)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("PRC107 on %q, want %q", got, tt.want)
			}
		})
	}
}
