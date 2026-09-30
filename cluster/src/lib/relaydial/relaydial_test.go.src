package relaydial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The relay the registry means is accepted.
func TestPinnedVerifier_AcceptsThePinnedCertificate(t *testing.T) {
	c := selfSigned(t, "relay-a")
	if err := PinnedVerifier("relay-a:9000", Fingerprint(c))([][]byte{c.Raw}, nil); err != nil {
		t.Fatalf("the pinned certificate was rejected: %v", err)
	}
}

// A DIFFERENT certificate is refused even though it is perfectly valid — which
// is the whole point, and the case a CA check would wave through.
func TestPinnedVerifier_RefusesAnotherValidCertificate(t *testing.T) {
	pinned := selfSigned(t, "relay-a")
	other := selfSigned(t, "relay-a") // same subject, different key
	err := PinnedVerifier("relay-a:9000", Fingerprint(pinned))([][]byte{other.Raw}, nil)
	if err == nil {
		t.Fatal("a certificate that is not the pinned one was accepted")
	}
	// The message has to distinguish rotation from impersonation, because the
	// operator's next action differs completely.
	for _, want := range []string{"relay-a:9000", "rotated", Fingerprint(pinned)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// No certificate at all is refused rather than treated as "nothing to check".
func TestPinnedVerifier_RefusesAnEmptyChain(t *testing.T) {
	if err := PinnedVerifier("x:1", "abc")(nil, nil); err == nil {
		t.Fatal("an empty chain was accepted")
	}
}

// An unpinned row is refused at DIAL time. Defaulting it to "accept anything"
// would turn an unfinished registry row into a silent downgrade to no identity
// check — the one failure this design exists to prevent.
func TestDial_RefusesAnEmptyPin(t *testing.T) {
	_, err := Dial(Config{}, "relay-a:9000", "   ")
	if err == nil {
		t.Fatal("a relay with no pinned fingerprint was dialled")
	}
	if !strings.Contains(err.Error(), "cert_fingerprint") {
		t.Errorf("the refusal does not name the missing field: %v", err)
	}
}
