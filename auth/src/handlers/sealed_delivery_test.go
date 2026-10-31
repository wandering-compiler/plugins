package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// testIdentity / testRecipient are the mailer's key pair the sealed paths
// are tested with; every handler a config test builds names testRecipient.
var testIdentity, testRecipient = func() (*age.X25519Identity, string) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	return id, id.Recipient().String()
}()

// openTest opens a sealed_* value the way the mailer does (the SDK's
// secret.OpenSealed is this: base64, then age).
func openTest(t *testing.T, sealed string) string {
	t.Helper()
	ct, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("sealed value is not base64: %v", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), testIdentity)
	if err != nil {
		t.Fatalf("the recipient's identity does not open it: %v", err)
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

// wantSealed checks one path's request: no credential in clear, a sealed one
// the identity opens, and that opened credential is the one stored hashed.
func wantSealed(t *testing.T, path, clear, sealed, hash string) string {
	t.Helper()
	if clear != "" {
		t.Errorf("%s: the credential travels in clear (%q) beside a recipient", path, clear)
	}
	if sealed == "" {
		t.Fatalf("%s: nothing sealed", path)
	}
	got := openTest(t, sealed)
	if hash != "" && sha256Hex(got) != hash {
		// The opened credential is the one whose hash was stored.
		t.Errorf("%s: the sealed credential is not the one stored", path)
	}
	if strings.Contains(sealed, got) {
		t.Errorf("%s: the sealed text carries the credential", path)
	}
	return got
}

func TestDeliver(t *testing.T) {
	h := &AuthServiceHandler{DeliveryRecipient: testRecipient}
	clear, sealed, err := h.deliver("123456")
	if err != nil || clear != "" || openTest(t, sealed) != "123456" {
		t.Errorf("with a recipient: clear %q, sealed opens to %q, %v", clear, openTest(t, sealed), err)
	}
	if c, s, err := h.deliver(""); c != "" || s != "" || err != nil {
		t.Errorf("an empty credential became %q / %q / %v", c, s, err)
	}
	plain := &AuthServiceHandler{}
	if c, s, err := plain.deliver("123456"); c != "123456" || s != "" || err != nil {
		t.Errorf("without a recipient (dev): %q / %q / %v", c, s, err)
	}
}

// Without a recipient the boot is refused wherever a credential would go on
// the bus, except W17_ENV=dev; a recipient that is not one, everywhere.
func TestCheckDeliveryRecipient(t *testing.T) {
	if len(secretDeliveryFeatures) == 0 {
		t.Fatal("no feature registered as delivering a credential — the check guards nothing")
	}
	for _, env := range []string{"", "prod", "staging"} {
		t.Setenv(envEnvironment, env)
		err := checkDeliveryRecipient(&AuthServiceHandler{})
		if err == nil || !strings.Contains(err.Error(), "delivery_recipient is required") || !strings.Contains(err.Error(), "password_reset") {
			t.Errorf("W17_ENV=%q, no recipient: %v, want a refusal naming the features", env, err)
		}
	}
	t.Setenv(envEnvironment, devEnvironment)
	if err := checkDeliveryRecipient(&AuthServiceHandler{}); err != nil {
		t.Errorf("dev without a recipient: %v", err)
	}
	for _, bad := range []string{"age1nope", "ssh-ed25519 AAAA", testIdentity.String()} {
		if err := checkDeliveryRecipient(&AuthServiceHandler{DeliveryRecipient: bad}); err == nil {
			t.Errorf("recipient %q booted (in dev, too)", bad)
		}
	}
	t.Setenv(envEnvironment, "prod")
	if err := checkDeliveryRecipient(&AuthServiceHandler{DeliveryRecipient: " " + testRecipient + "\n"}); err != nil {
		t.Errorf("a recipient: %v", err)
	}
}

// Each of the five paths puts its credential on the event sealed, never in
// clear, when a recipient is configured. One test per path: the sign-up path
// pins its own activation for the rest of its test.
func TestSealedDelivery_PasswordReset(t *testing.T) {
	m := &tokenFlowMock{userByEmail: map[string]*pb.User{"u@x.com": {Id: "u1", Email: "u@x.com"}}}
	h := newTokenFlowHandler(m)
	h.DeliveryRecipient = testRecipient
	if _, err := h.RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "u@x.com"}); err != nil {
		t.Fatal(err)
	}
	wantSealed(t, "password reset", m.createdReset.GetToken(), m.createdReset.GetSealedToken(), m.createdReset.GetTokenHash())
}

func TestSealedDelivery_EmailVerification(t *testing.T) {
	m := &tokenFlowMock{userByID: map[string]*pb.User{"u1": {Id: "u1", Email: "u@x.com"}}}
	h := newTokenFlowHandler(m)
	h.DeliveryRecipient = testRecipient
	if _, err := h.RequestEmailVerification(ctxWithCaller("u1"), &pb.RequestEmailVerificationReq{}); err != nil {
		t.Fatal(err)
	}
	wantSealed(t, "email verification", m.createdVerify.GetToken(), m.createdVerify.GetSealedToken(), m.createdVerify.GetTokenHash())
}

func TestSealedDelivery_SignUpConfirmation(t *testing.T) {
	ch, s := confirmHandler(t)
	ch.DeliveryRecipient = testRecipient
	if _, err := ch.SignUp(withJKT(context.Background(), testJKT), &pb.SignUpReq{Email: "new@example.com", Password: "pw-owner"}); err != nil {
		t.Fatal(err)
	}
	code := wantSealed(t, "sign-up confirmation", s.lastCreate.GetCode(), s.lastCreate.GetSealedCode(), "")
	if s.lastCreate.GetCodeHash() == "" || len(code) != signUpCodeLength {
		t.Errorf("sign-up: opened code %q does not look like one", code)
	}
}

func TestSealedDelivery_SecondFactor(t *testing.T) {
	mm := &mfaMock{userEmail: "a@b.c"}
	mh := newMfaHandler(mm)
	mh.DeliveryRecipient = testRecipient
	if _, _, err := signInMfaGate(context.Background(), mh, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil {
		t.Fatal(err)
	}
	code := wantSealed(t, "second factor", mm.createdChallenge.GetCode(), mm.createdChallenge.GetSealedCode(), "")
	if len(code) != mfaCodeDigits {
		t.Errorf("second factor: opened code %q does not look like one", code)
	}
}

func TestSealedDelivery_StepUpCode(t *testing.T) {
	sh, sm := newStepUpCodeHandler(false)
	sh.DeliveryRecipient = testRecipient
	if _, err := sh.RequestStepUpCode(sessionCallerCtx("u1", "tok-1"), &pb.RequestStepUpCodeReq{}); err != nil {
		t.Fatal(err)
	}
	wantSealed(t, "step-up code", sm.sent[0].GetCode(), sm.sent[0].GetSealedCode(), "")
}

// A challenge the authenticator answers carries no code: nothing to seal.
func TestSealedDelivery_AnAuthenticatorChallengeCarriesNothing(t *testing.T) {
	mm := &mfaMock{userEmail: "a@b.c", totpSeed: "x", totpConfirmed: true}
	mh := newMfaHandler(mm)
	mh.DeliveryRecipient = testRecipient
	if _, _, err := signInMfaGate(context.Background(), mh, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil {
		t.Fatal(err)
	}
	if mm.createdChallenge.GetCode() != "" || mm.createdChallenge.GetSealedCode() != "" {
		t.Errorf("an authenticator challenge carried %q / %q", mm.createdChallenge.GetCode(), mm.createdChallenge.GetSealedCode())
	}
}
