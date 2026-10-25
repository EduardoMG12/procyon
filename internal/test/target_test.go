package test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeLookup resolves names from a table; literal IPs resolve to themselves,
// like the real resolver.
func fakeLookup(names map[string][]string) lookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if addr, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{addr}, nil
		}
		var addrs []netip.Addr
		for _, s := range names[host] {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		if addrs == nil {
			return nil, errors.New("no such host")
		}
		return addrs, nil
	}
}

func TestCheckTarget(t *testing.T) {
	lookup := fakeLookup(map[string][]string{
		"localhost":   {"127.0.0.1", "::1"},
		"api":         {"172.18.0.2"},
		"example.com": {"93.184.215.14"},
		"rebind.test": {"10.0.0.5", "93.184.215.14"},
	})
	tests := []struct {
		url   string
		error string // substring; "" means allowed
	}{
		{"http://127.0.0.1:8080", ""},
		{"http://localhost:8080/v1", ""},
		{"https://api", ""},
		{"http://10.1.2.3", ""},
		{"http://192.168.0.10", ""},
		{"http://[::1]:8080", ""},
		{"http://[fd00::1]", ""},
		{"http://example.com", "93.184.215.14, which is not a loopback or private address"},
		{"http://rebind.test", "93.184.215.14"},
		{"http://8.8.8.8", "not a loopback or private address"},
		{"http://[::ffff:8.8.8.8]", "not a loopback or private address"},
		{"http://172.32.0.1", "not a loopback or private address"}, // just past 172.16.0.0/12
		{"ftp://127.0.0.1", "want an http:// or https:// URL"},
		{"127.0.0.1:8080", "want an http:// or https:// URL"},
		{"http://", "no host"},
		{"http://nowhere.test", "no such host"},
	}
	for _, tt := range tests {
		_, err := checkTarget(context.Background(), tt.url, lookup)
		switch {
		case tt.error == "" && err != nil:
			t.Errorf("checkTarget(%q) = %v, want allowed", tt.url, err)
		case tt.error != "" && (err == nil || !strings.Contains(err.Error(), tt.error)):
			t.Errorf("checkTarget(%q) = %v, want an error containing %q", tt.url, err, tt.error)
		}
	}
}

func TestCheckDialRefusesPublicAddresses(t *testing.T) {
	if err := checkDial("tcp", "127.0.0.1:80", nil); err != nil {
		t.Errorf("loopback: %v", err)
	}
	if err := checkDial("tcp", "8.8.8.8:443", nil); !errors.Is(err, errNotAllowed) {
		t.Errorf("public address: %v, want errNotAllowed", err)
	}
}

func get(t *testing.T, c *client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.do(req)
	if err == nil {
		resp.Body.Close()
	}
	return resp, err
}

func TestClientDoesNotFollowRedirectsToAnotherHost(t *testing.T) {
	var reached bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer other.Close()
	// "localhost" and "127.0.0.1" are different hosts for the redirect check,
	// though both are loopback.
	elsewhere := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/done", http.StatusFound)
			return
		}
		if r.URL.Path == "/done" {
			return
		}
		http.Redirect(w, r, elsewhere, http.StatusFound)
	}))
	defer target.Close()
	base, _ := url.Parse(target.URL)
	c := newClient(base, time.Second, 10)

	resp, err := get(t, c, target.URL+"/away")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound || reached {
		t.Errorf("redirect to another host: status %d, other host reached %v; want 302 and not reached", resp.StatusCode, reached)
	}
	resp, err = get(t, c, target.URL+"/same")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("redirect on the same host: status %d, want it followed to 200", resp.StatusCode)
	}
}

func TestClientTimeoutAndBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(300 * time.Millisecond)
		}
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	c := newClient(base, 50*time.Millisecond, 2)

	if _, err := get(t, c, srv.URL+"/slow"); err == nil {
		t.Error("a slow answer did not time out")
	}
	if _, err := get(t, c, srv.URL+"/fast"); err != nil {
		t.Errorf("second request: %v", err)
	}
	if _, err := get(t, c, srv.URL+"/fast"); !errors.Is(err, errBudget) {
		t.Errorf("third request with a budget of 2: %v, want errBudget", err)
	}
}
