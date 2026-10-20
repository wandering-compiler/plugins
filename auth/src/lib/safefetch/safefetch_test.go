package safefetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestPublic(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "240.0.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::", "::ffff:127.0.0.1", "::ffff:10.0.0.1"} {
		if Public(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "160.79.104.10", "2606:4700::1111"} {
		if !Public(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as not public", s)
		}
	}
}

func TestGet_RefusesTheURL(t *testing.T) {
	for _, u := range []string{"http://example.com/c.json", "https://127.0.0.1/c.json", "https://[::1]/c.json",
		"https://user:pw@example.com/c.json", "ftp://example.com/x", "not a url", "https://example.com/#f"} {
		if _, err := Get(context.Background(), u, Options{}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// A name that resolves to a private address is refused at the dial.
func TestGet_RefusesAPrivateAddressBehindAName(t *testing.T) {
	_, err := Get(context.Background(), "https://localhost:1/c.json", Options{})
	if !errors.Is(err, ErrRefused) {
		t.Errorf("localhost: %v", err)
	}
}

func TestGet_BodyCapAndRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	// httptest serves 127.0.0.1 under its certificate; name it "localhost"
	// and let the test admit loopback.
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	allow := func(netip.Addr) bool { return true }
	// The test server's certificate is its own, issued for example.com.
	tc := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tc.ServerName = "example.com"
	get := func(p string, max int64) ([]byte, error) {
		return Get(context.Background(), base+p, Options{AllowAddr: allow, MaxBytes: max, tlsConfig: tc})
	}
	if b, err := get("/ok", 0); err != nil || string(b) != `{"ok":true}` {
		t.Errorf("ok: %q %v", b, err)
	}
	if _, err := get("/big", 10); err == nil {
		t.Error("an oversized body was accepted")
	}
	if _, err := get("/moved", 0); err == nil {
		t.Error("a redirect was followed or accepted")
	}
}
