package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

// tlsServer starts an https server with cfg and returns its URL with host.
func tlsServer(t *testing.T, cfg *tls.Config, host string) *url.URL {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = cfg // StartTLS adds httptest's certificate when cfg has none
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	u.Host = net.JoinHostPort(host, port)
	return u
}

func problems(t *testing.T, target *url.URL) string {
	t.Helper()
	got, _ := checkTLS(context.Background(), target, 2*time.Second)
	var whats []string
	for _, p := range got {
		whats = append(whats, p.what)
	}
	return strings.Join(whats, "; ")
}

func TestCheckTLS(t *testing.T) {
	// httptest's certificate is self-signed, for example.com, 127.0.0.1 and ::1.
	tests := []struct {
		name string
		cfg  *tls.Config
		host string
		want string // problems, joined
	}{
		{"modern", nil, "127.0.0.1", ""},
		{"TLS 1.3 only", &tls.Config{MinVersion: tls.VersionTLS13}, "127.0.0.1", ""},
		{"IPv6", nil, "::1", ""},
		{"TLS 1.0 with a legacy suite only", &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}, "127.0.0.1", "accepts TLS 1.0; accepts the weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA"},
		{"TLS 1.1 with 3DES only", &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}, "127.0.0.1", "accepts TLS 1.1; accepts the weak cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{"weak suite on TLS 1.2", &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA256}}, "127.0.0.1", "accepts the weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA256"},
		// Self-signed: name and dates are not judged, anyone can mint them.
		{"self-signed for another host", nil, "localhost", ""},
		{"self-signed and expired", &tls.Config{Certificates: []tls.Certificate{expiredCert(t)}}, "127.0.0.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := problems(t, tlsServer(t, tt.cfg, tt.host)); got != tt.want {
				t.Errorf("problems = %q, want %q", got, tt.want)
			}
		})
	}
}

// A probe checkDial refuses is a note, never a silent pass.
func TestCheckTLSNotesWhatItCannotCheck(t *testing.T) {
	public, _ := url.Parse("https://8.8.8.8")
	if got, note := checkTLS(context.Background(), public, time.Second); len(got) != 0 || !strings.Contains(note, "not a loopback or private address") {
		t.Errorf("public address: %v, %q; want it refused by checkDial", got, note)
	}
}

// A server that speaks only TLS 1.1 is reported, and the run goes on.
func TestRunAgainstAnOldTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(vulnapi.New(true))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	rep, err := Run(context.Background(), vulnapiSpec, Options{BaseURL: srv.URL, TokenA: vulnapi.TokenA, TokenB: vulnapi.TokenB})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule.ID != "PRC105" || !strings.Contains(rep.Findings[0].Why, "accepts TLS 1.1") {
		t.Errorf("findings = %v, want PRC105 for TLS 1.1", rep.Findings)
	}
	if len(rep.Matrix) == 0 || rep.Matrix[1].A.Outcome != "allowed" {
		t.Errorf("the run did not go on: matrix %v", rep.Matrix)
	}
}

// expiredCert is a self-signed certificate for 127.0.0.1 that expired.
func expiredCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
