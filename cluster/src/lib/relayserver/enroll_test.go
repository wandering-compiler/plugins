package relayserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

type enrolRig struct {
	e     *Enrollment
	ca    *identity.CA
	codes *regcode.Store
	reg   *workeradmit.Registry
	now   time.Time
}

func newEnrolRig(t *testing.T) *enrolRig {
	t.Helper()
	ca, err := identity.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := regcode.New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &enrolRig{ca: ca, codes: codes, reg: workeradmit.New(), now: time.Now()}
	r.e = &Enrollment{CA: ca, Codes: codes, Workers: r.reg, Lifetime: time.Hour, Now: func() time.Time { return r.now }}
	return r
}

func (r *enrolRig) code(t *testing.T) string {
	t.Helper()
	c, _, err := r.codes.Issue()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// withPeer is a context as the attach listener hands it over: the client
// certificate the handshake verified, or none.
func withPeer(cert *x509.Certificate) context.Context {
	st := tls.ConnectionState{}
	if cert != nil {
		st.PeerCertificates = []*x509.Certificate{cert}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: st}})
}

func enrol(t *testing.T, r *enrolRig) (keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	keyPEM, csr, err := identity.NewKeyAndCSR("w1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: r.code(t), Csr: csr, Name: "w1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	cert, err = identity.ParseCertificatePEM(resp.GetCertificatePem())
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, cert
}

// A code buys a certificate for the worker's OWN key, from this relay's CA,
// and the worker is then known to the relay under that key's fingerprint.
func TestEnroll_ACodeBuysACertificateForTheWorkersKey(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, cert := enrol(t, r)
	if err := r.ca.Verify(cert, time.Now()); err != nil {
		t.Fatalf("the issued certificate does not chain to the relay's CA: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM(cert), keyPEM); err != nil {
		t.Fatalf("the certificate is not for the key the worker generated: %v", err)
	}
	known := r.reg.Known()
	if len(known) != 1 || known[0].ID != identity.WorkerID(cert) || known[0].Name != "w1" {
		t.Errorf("known = %+v, want the enrolled worker under its key's fingerprint", known)
	}
}

// A code works once; a refused one never says why.
func TestEnroll_ACodeIsSingleUse(t *testing.T) {
	r := newEnrolRig(t)
	code := r.code(t)
	_, csr, _ := identity.NewKeyAndCSR("a")
	if _, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr}); err != nil {
		t.Fatal(err)
	}
	_, csr2, _ := identity.NewKeyAndCSR("b")
	_, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr2})
	if got := refusal.ReasonOf(err); got != refusal.RegistrationCodeInvalid {
		t.Fatalf("a spent code: %v (reason %q), want %s", err, got, refusal.RegistrationCodeInvalid)
	}
}

// A malformed request does NOT spend the code: an operator should not have to
// issue a second one because the worker sent garbage first.
func TestEnroll_AMalformedRequestDoesNotSpendTheCode(t *testing.T) {
	r := newEnrolRig(t)
	code := r.code(t)
	if _, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: []byte("nope")}); err == nil {
		t.Fatal("a malformed request was accepted")
	}
	_, csr, _ := identity.NewKeyAndCSR("a")
	if _, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr}); err != nil {
		t.Fatalf("the code was spent by a malformed request: %v", err)
	}
}

// A banned key cannot buy a certificate, not even with a fresh code.
func TestEnroll_ABannedKeyIsRefused(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, _, _ := identity.NewKeyAndCSR("a")
	csr, _ := identity.CSRFor(keyPEM, "a")
	parsed, _ := identity.ParseCSR(csr)
	id, _ := identity.PublicKeyID(parsed.PublicKey)
	r.reg.SetBanned([]string{id})
	_, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: r.code(t), Csr: csr})
	if got := refusal.ReasonOf(err); got != refusal.WorkerBanned {
		t.Fatalf("a banned key enrolled: %v (reason %q)", err, got)
	}
}

// A banned key is told it is BANNED even when its claims are also unusable —
// the ban is the answer that matters, and checking the claims first sent the
// worker off to fix a name only to be refused again for its key. Neither
// refusal spends the code.
func TestEnroll_ABannedKeyHearsTheBanBeforeItsClaims(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, _, _ := identity.NewKeyAndCSR("a")
	csr, _ := identity.CSRFor(keyPEM, "a")
	parsed, _ := identity.ParseCSR(csr)
	id, _ := identity.PublicKeyID(parsed.PublicKey)
	r.reg.SetBanned([]string{id})
	code := r.code(t)
	_, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr, Name: "acme\x001"})
	if got := refusal.ReasonOf(err); got != refusal.WorkerBanned {
		t.Fatalf("a banned key with a bad name: %v (reason %q), want %s", err, got, refusal.WorkerBanned)
	}
	_, csr2, _ := identity.NewKeyAndCSR("b")
	if _, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr2, Name: "acme-2"}); err != nil {
		t.Errorf("the banned key's refusal spent the code: %v", err)
	}
}

// Renewal keeps the KEY, so the identity survives it — the registry row and
// any ban keep pointing at this worker.
func TestRenew_KeepsTheIdentity(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, cert := enrol(t, r)
	csr, _ := identity.CSRFor(keyPEM, "w1")
	resp, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: csr})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	renewed, _ := identity.ParseCertificatePEM(resp.GetCertificatePem())
	if identity.WorkerID(renewed) != identity.WorkerID(cert) {
		t.Error("renewal changed the worker's identity")
	}
	if renewed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("renewal renamed the certificate: %q → %q", cert.Subject.CommonName, renewed.Subject.CommonName)
	}
}

// Every way a renewal must fail, each with the reason that tells the worker it
// needs a new code (or that it is banned).
func TestRenew_Refusals(t *testing.T) {
	r := newEnrolRig(t)
	keyPEM, cert := enrol(t, r)
	csr, _ := identity.CSRFor(keyPEM, "w1")

	other, _ := identity.LoadOrCreateCA(t.TempDir())
	oc, _ := identity.ParseCSR(csr)
	foreignPEM, _ := other.IssueClientCert(oc.PublicKey, "w1", time.Hour)
	foreign, _ := identity.ParseCertificatePEM(foreignPEM)

	_, otherCSR, _ := identity.NewKeyAndCSR("x")

	for _, tc := range []struct {
		name   string
		ctx    context.Context
		csr    []byte
		before func()
		want   string
	}{
		{"no certificate", withPeer(nil), csr, nil, refusal.CertificateNotRenewable},
		{"another relay's certificate", withPeer(foreign), csr, nil, refusal.CertificateNotRenewable},
		{"a request for another key", withPeer(cert), otherCSR, nil, refusal.CertificateNotRenewable},
		{"expired", withPeer(cert), csr, func() { r.now = time.Now().Add(2 * time.Hour) }, refusal.CertificateNotRenewable},
		{"banned", withPeer(cert), csr, func() { r.now = time.Now(); r.reg.SetBanned([]string{identity.WorkerID(cert)}) }, refusal.WorkerBanned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}
			_, err := r.e.Renew(tc.ctx, &workerpb.RenewReq{Csr: tc.csr})
			if got := refusal.ReasonOf(err); got != tc.want {
				t.Fatalf("err = %v (reason %q), want %s", err, got, tc.want)
			}
		})
	}
}

// The interceptor applies a ban set that is THERE, including an empty one,
// and leaves the registry alone when the header is absent.
func TestBanInterceptors_ApplyOnlyWhatWasSent(t *testing.T) {
	reg := workeradmit.New()
	unary, _ := BanInterceptors(reg)
	call := func(md metadata.MD) {
		ctx := metadata.NewIncomingContext(context.Background(), md)
		_, _ = unary(ctx, nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) { return nil, nil })
	}
	call(metadata.Pairs(workeradmit.BannedHeader, "aa"))
	if reg.Admitted("aa") {
		t.Fatal("a ban set on the call was not applied")
	}
	call(metadata.MD{})
	if reg.Admitted("aa") {
		t.Error("a call WITHOUT the header lifted the bans")
	}
	call(metadata.Pairs(workeradmit.BannedHeader, ""))
	if !reg.Admitted("aa") {
		t.Error("an empty ban set did not lift the ban")
	}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
