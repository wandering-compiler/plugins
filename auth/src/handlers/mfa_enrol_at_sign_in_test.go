package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// two_factor_policy=enrol: every account is challenged, and one without a
// confirmed authenticator sets it up at sign-in instead of getting a code.

// enrolFixture is the MFA store under the enrol default, with no
// organization in play.
func enrolFixture() (*policyMock, *AuthServiceHandler) {
	m, h := policyFixture()
	m.orgs = nil
	h.TwoFactorPolicy = policyEnrol
	return m, h
}

// enrolChallenge runs the sign-in gate and returns its answer.
func enrolChallenge(t *testing.T, h *AuthServiceHandler) *pb.SignInResp {
	t.Helper()
	resp, ok, err := mfaSignInGate(signInFor("", ""), h, gateUser(), testJKT, false, false)
	if err != nil || !ok {
		t.Fatalf("sign-in gate: challenged=%v err=%v", ok, err)
	}
	return resp
}

// An account without an authenticator gets an enrolment challenge: no code
// is generated and no CreateMfaChallenge runs, so MfaChallengeRequested —
// which a delivery channel would answer with an empty code — never fires.
func TestEnrolAtSignIn_AnUnenrolledAccountGetsAnEnrolmentChallenge(t *testing.T) {
	m, h := enrolFixture()
	resp := enrolChallenge(t, h)
	if !resp.GetMfaRequired() || !resp.GetEnrolmentRequired() || resp.GetChallengeId() == "" || resp.GetToken() != "" {
		t.Fatalf("SignIn answered %v, want mfa_required + enrolment_required + a challenge and no token", resp)
	}
	if m.createdChallenge != nil {
		t.Fatalf("a code challenge was created (%v) — its event would send an empty code", m.createdChallenge)
	}
	if e := m.createdEnrolment; e == nil || e.GetThumbprint() != testJKT || e.GetUserId() != "u1" {
		t.Fatalf("the enrolment challenge is %v, want u1's, bound to the sign-in's key", e)
	}
	// Through the issuance seam: superseded first, under the cap.
	if strings.Join(m.ops, ",") != "lock:u1,supersede:u1,create-enrolment" {
		t.Fatalf("issuance ops = %v, want the supersede then the enrolment challenge", m.ops)
	}
}

// An account that has an authenticator is challenged for its code, as under
// required.
func TestEnrolAtSignIn_AnEnrolledAccountIsAskedForItsCode(t *testing.T) {
	m, h := enrolFixture()
	m.enrol()
	resp := enrolChallenge(t, h)
	if resp.GetEnrolmentRequired() || m.createdEnrolment != nil {
		t.Fatalf("an enrolled account got an enrolment challenge: %v", resp)
	}
	if c := m.createdChallenge; c == nil || !c.GetTotpEnrolled() || c.GetCode() != "" {
		t.Fatalf("the challenge is %v, want the authenticator's (no code)", c)
	}
}

// The whole flow: the enrolment on the challenge, then VerifyMfa with the
// new authenticator's first code — confirmed, ten recovery codes, the
// session, the device trusted.
func TestEnrolAtSignIn_EnrolThenVerifySignsIn(t *testing.T) {
	m, h := enrolFixture()
	resp := enrolChallenge(t, h)
	ctx := withJKT(context.Background(), testJKT)

	enrolment, err := h.EnrollTotpAtSignIn(ctx, &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()})
	if err != nil {
		t.Fatalf("EnrollTotpAtSignIn: %v", err)
	}
	if enrolment.GetSecret() == "" || !strings.HasPrefix(enrolment.GetOtpauthUri(), "otpauth://") || !strings.Contains(enrolment.GetQrSvg(), "<svg") {
		t.Fatalf("the enrolment answered %v, want a secret, its URI and a QR code", enrolment)
	}
	if m.totpConfirmed {
		t.Fatal("the authenticator is confirmed before any code from it")
	}

	code, _ := totp.Code(enrolment.GetSecret(), time.Now())
	v, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: resp.GetChallengeId(), Code: code})
	if err != nil {
		t.Fatalf("VerifyMfa with the new authenticator's code: %v", err)
	}
	if v.GetUserId() != "u1" || m.issuedHash == "" {
		t.Fatalf("VerifyMfa answered %v and issued %q, want u1's session", v, m.issuedHash)
	}
	if !m.confirmedTotp {
		t.Fatal("the authenticator set up at sign-in was not confirmed")
	}
	if len(v.GetRecoveryCodes()) != recoveryCodeCount {
		t.Fatalf("recovery codes = %d, want %d", len(v.GetRecoveryCodes()), recoveryCodeCount)
	}
	if m.trustedDevice == nil {
		t.Fatal("passing the second factor did not trust the device")
	}
	if !m.chConsumed {
		t.Fatal("the challenge was not consumed")
	}
}

// A wrong first code confirms nothing, issues nothing, and spends an attempt.
func TestEnrolAtSignIn_AWrongCodeConfirmsNothing(t *testing.T) {
	m, h := enrolFixture()
	resp := enrolChallenge(t, h)
	ctx := withJKT(context.Background(), testJKT)
	if _, err := h.EnrollTotpAtSignIn(ctx, &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()}); err != nil {
		t.Fatalf("EnrollTotpAtSignIn: %v", err)
	}
	_, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: resp.GetChallengeId(), Code: "000000"})
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeMfaCodeRefused {
		t.Fatalf("a wrong code: %v, want the code-refused pair", err)
	}
	if m.confirmedTotp || m.issuedHash != "" || m.chConsumed || m.chAttempts != 1 {
		t.Fatalf("confirmed=%v issued=%q consumed=%v attempts=%d, want one attempt spent and nothing else",
			m.confirmedTotp, m.issuedHash, m.chConsumed, m.chAttempts)
	}
}

// VerifyMfa before any enrolment has no authenticator to check against.
func TestEnrolAtSignIn_VerifyBeforeTheEnrolmentRefuses(t *testing.T) {
	m, h := enrolFixture()
	resp := enrolChallenge(t, h)
	_, err := h.VerifyMfa(withJKT(context.Background(), testJKT), &pb.VerifyMfaReq{ChallengeId: resp.GetChallengeId(), Code: "123456"})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("VerifyMfa with nothing enrolled: %v, want the opaque refusal", err)
	}
	if m.issuedHash != "" {
		t.Fatal("a session was issued")
	}
}

// The enrolment refuses, as opaquely as a wrong code, every challenge it is
// not for: another key's, a code challenge, a spent, expired or exhausted
// one, and one whose account has confirmed an authenticator since.
func TestEnrolAtSignIn_TheEnrolmentRefusesWhatItIsNotFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		jkt   string
		alter func(m *policyMock)
	}{
		{"another key", otherJKT, func(*policyMock) {}},
		{"a code challenge", testJKT, func(m *policyMock) { m.chEnrol = false }},
		{"a consumed challenge", testJKT, func(m *policyMock) { m.chConsumed = true }},
		{"an expired challenge", testJKT, func(m *policyMock) { m.chCreatedAt = timestamppb.New(time.Now().Add(-time.Hour)) }},
		{"no creation time", testJKT, func(m *policyMock) { m.chCreatedAt = nil }},
		{"its attempts spent", testJKT, func(m *policyMock) { m.chAttempts = maxMfaAttempts }},
		{"an authenticator confirmed since", testJKT, func(m *policyMock) { m.enrol() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, h := enrolFixture()
			resp := enrolChallenge(t, h)
			tc.alter(m)
			seed := m.totpSeed
			_, err := h.EnrollTotpAtSignIn(withJKT(context.Background(), tc.jkt), &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()})
			if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeMfaCodeRefused || d.GetMessage() != MsgMfaCodeRefused {
				t.Fatalf("err = %v, want the code-refused pair a wrong code gets", err)
			}
			if m.totpSeed != seed {
				t.Fatal("a refused enrolment replaced the authenticator")
			}
		})
	}
}

// Without the built-in authenticator there is nothing to set up.
func TestEnrolAtSignIn_TheEnrolmentNeedsTheAuthenticator(t *testing.T) {
	m, h := enrolFixture()
	resp := enrolChallenge(t, h)
	h.TwoFactorTOTP = false
	_, err := h.EnrollTotpAtSignIn(withJKT(context.Background(), testJKT), &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()})
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeTotpUnavailable {
		t.Fatalf("err = %v, want TOTP_UNAVAILABLE", err)
	}
	if m.totpSeed != "" {
		t.Fatal("an authenticator was stored")
	}
}

// Calling the enrolment again replaces the authenticator not yet confirmed:
// only the latest one's code completes the sign-in.
func TestEnrolAtSignIn_ASecondEnrolmentReplacesTheFirst(t *testing.T) {
	_, h := enrolFixture()
	resp := enrolChallenge(t, h)
	ctx := withJKT(context.Background(), testJKT)
	first, err := h.EnrollTotpAtSignIn(ctx, &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.EnrollTotpAtSignIn(ctx, &pb.EnrollTotpAtSignInReq{ChallengeId: resp.GetChallengeId()})
	if err != nil {
		t.Fatal(err)
	}
	if first.GetSecret() == second.GetSecret() {
		t.Fatal("the second enrolment answered the first one's secret")
	}
	code, _ := totp.Code(second.GetSecret(), time.Now())
	if _, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: resp.GetChallengeId(), Code: code}); err != nil {
		t.Fatalf("the latest authenticator's code: %v", err)
	}
}

// With the built-in authenticator off, enrol cannot hold: the boot refuses
// it as the activation's default, an organization cannot set it, and one set
// before the authenticator went off challenges by message, as required does.
func TestEnrolAtSignIn_EnrolNeedsTheBuiltInAuthenticator(t *testing.T) {
	if err := checkTwoFactorPolicy(&AuthServiceHandler{TwoFactorPolicy: policyEnrol, TwoFactorTOTP: false}); err == nil {
		t.Error("two_factor_policy=enrol with two_factor_totp=false booted")
	}
	if err := checkTwoFactorPolicy(&AuthServiceHandler{TwoFactorPolicy: policyEnrol, TwoFactorTOTP: true}); err != nil {
		t.Errorf("two_factor_policy=enrol refused: %v", err)
	}

	m, h := policyFixture()
	h.TwoFactorTOTP = false
	h.Lock = policyLock("SetOrgTwoFactorPolicy")
	_, err := h.SetOrgTwoFactorPolicy(whoAmICtx("ops", ""), &pb.SetOrgTwoFactorPolicyReq{OrgId: "org-acme", Policy: policyEnrol})
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeTwoFactorPolicyInvalid || d.GetMessage() != MsgTwoFactorEnrolUnavailable {
		t.Fatalf("an organization set enrol without the authenticator: %v", err)
	}
	if len(m.set) != 0 {
		t.Fatalf("a refused policy was written: %v", m.set)
	}

	m, h = policyFixture()
	h.TwoFactorTOTP = false
	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyEnrol}}
	resp, ok, err := mfaSignInGate(signInFor("acme", ""), h, gateUser(), testJKT, false, false)
	if err != nil || !ok || resp.GetEnrolmentRequired() {
		t.Fatalf("enrol with the authenticator off: %v challenged=%v err=%v, want a code challenge", resp, ok, err)
	}
	if c := m.createdChallenge; c == nil || c.GetCode() == "" && c.GetSealedCode() == "" {
		t.Fatalf("the challenge is %v, want a code by message", c)
	}
}

// An organization's enrol decides over the activation's default.
func TestEnrolAtSignIn_TheOrganizationDecides(t *testing.T) {
	m, h := policyFixture()
	h.TwoFactorPolicy = policyOptional
	if challenged(t, h, signInFor("acme", "")) {
		t.Fatal("optional, no authenticator: challenged")
	}
	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyEnrol}}
	resp, ok, err := mfaSignInGate(signInFor("acme", ""), h, gateUser(), testJKT, false, false)
	if err != nil || !ok || !resp.GetEnrolmentRequired() {
		t.Fatalf("acme's enrol: %v challenged=%v err=%v, want an enrolment challenge", resp, ok, err)
	}
}

// Where two_factor_enrolment is not staged (its seams nil): enrol refuses the
// boot and an organization's policy, an organization's enrol set before the
// feature went off challenges by message, and VerifyMfa completes no
// enrolment challenge.
func TestEnrolAtSignIn_WithoutTheFeatureEnrolDoesNotHold(t *testing.T) {
	savedChallenge, savedConfirm := enrolmentChallenge, confirmEnrolment
	enrolmentChallenge, confirmEnrolment = nil, nil
	t.Cleanup(func() { enrolmentChallenge, confirmEnrolment = savedChallenge, savedConfirm })

	if err := checkTwoFactorPolicy(&AuthServiceHandler{TwoFactorPolicy: policyEnrol, TwoFactorTOTP: true}); err == nil || !strings.Contains(err.Error(), "two_factor_enrolment") {
		t.Errorf("enrol without the feature booted: %v", err)
	}

	m, h := policyFixture()
	h.Lock = policyLock("SetOrgTwoFactorPolicy")
	_, err := h.SetOrgTwoFactorPolicy(whoAmICtx("ops", ""), &pb.SetOrgTwoFactorPolicyReq{OrgId: "org-acme", Policy: policyEnrol})
	if d := errorDetailOf(t, err); d == nil || d.GetMessage() != MsgTwoFactorEnrolUnavailable {
		t.Fatalf("an organization set enrol without the feature: %v", err)
	}

	m.policies["org-acme"] = []*pb.OrgTwoFactorPolicyRow{{Kind: "", Policy: policyEnrol}}
	h.TwoFactorTOTP = false // the code path: a code for the channel
	resp, ok, err := mfaSignInGate(signInFor("acme", ""), h, gateUser(), testJKT, false, false)
	if err != nil || !ok || resp.GetEnrolmentRequired() || m.createdChallenge == nil {
		t.Fatalf("enrol without the feature: %v challenged=%v err=%v, want a code challenge", resp, ok, err)
	}

	m.chEnrol = true // a challenge raised while the feature was on
	if _, err := h.VerifyMfa(withJKT(context.Background(), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: m.createdChallenge.GetCode()}); err == nil || m.issuedHash != "" {
		t.Fatalf("VerifyMfa completed an enrolment challenge without the feature: err=%v issued=%q", err, m.issuedHash)
	}
}
