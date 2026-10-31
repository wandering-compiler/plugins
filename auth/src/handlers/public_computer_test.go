package handlers

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// device/public-computer (the server's half): a sign-in marked "this is a
// public computer" never makes the device trusted — nor leans on trust it had
// — gets the public session lifetime, and is recorded as such on the session
// and in the sign-in history. Keeping the token in session storage is the
// client's half (phase 5); the server echoes the choice so the client can.

// within reports whether ts is d from now, give or take a few seconds.
func within(ts *timestamppb.Timestamp, d time.Duration) bool {
	got := time.Until(ts.AsTime())
	return got > d-5*time.Second && got < d+5*time.Second
}

// SignIn on a TRUSTED device: a normal sign-in renews the trust and gets the
// session lifetime; a public one neither renews nor uses it (the second-factor
// gate is told the device is untrusted, and is told it is public), gets the
// public lifetime, and the session, the response and the history row all say
// public.
func TestSignIn_PublicComputer_NoTrustAndTheShortLifetime(t *testing.T) {
	for _, public := range []bool{false, true} {
		saved := signInMfaGate
		var gateTrusted, gatePublic bool
		signInMfaGate = func(_ context.Context, _ *AuthServiceHandler, _ *pb.User, _ string, trusted, pub bool) (*pb.SignInResp, bool, error) {
			gateTrusted, gatePublic = trusted, pub
			return nil, false, nil
		}
		m, h := newSignInStore(t, "u1")
		h.SessionTokenTTLSeconds, h.PublicSessionTTLSeconds = 86400, 3600
		log := keepHistory(h)
		m.put("u1", testJKT, &pb.Device{TrustedAt: timestamppb.Now()})

		resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword, PublicComputer: public})
		signInMfaGate = saved
		if err != nil {
			t.Fatalf("public=%v: %v", public, err)
		}
		if resp.GetPublicComputer() != public {
			t.Errorf("public=%v: the response says %v", public, resp.GetPublicComputer())
		}
		if gateTrusted == public || gatePublic != public {
			t.Errorf("public=%v: the second-factor gate was told trusted=%v public=%v", public, gateTrusted, gatePublic)
		}
		if renewed := len(m.trusted) == 1; renewed == public {
			t.Errorf("public=%v: trust renewed = %v", public, renewed)
		}
		issued := m.issued[0]
		if issued.GetPublicComputer() != public {
			t.Errorf("public=%v: the session records public=%v", public, issued.GetPublicComputer())
		}
		wantTTL := 24 * time.Hour
		if public {
			wantTTL = time.Hour
		}
		if !within(issued.GetExpiresAt(), wantTTL) {
			t.Errorf("public=%v: the session expires in %v, want %v", public, time.Until(issued.GetExpiresAt().AsTime()), wantTTL)
		}
		if len(log.rows) != 1 || log.rows[0].GetPublicComputer() != public {
			t.Errorf("public=%v: history %v", public, log.rows)
		}
	}
}

// With two_factor_scope=new_devices, a TRUSTED device skips the second factor
// — unless the sign-in is public: SignIn then hands the gate an untrusted
// device (TestSignIn_PublicComputer_NoTrustAndTheShortLifetime), the factor is
// asked as for a new device, and the challenge carries the choice to
// VerifyMfa.
func TestSignIn_PublicComputer_AsksTheSecondFactorOnATrustedDevice(t *testing.T) {
	for _, public := range []bool{false, true} {
		m := &mfaMock{userEmail: "a@b.c"}
		h := newMfaHandler(m)
		h.TwoFactorScope = scopeNewDevices
		_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, !public, public)
		if err != nil {
			t.Fatal(err)
		}
		if challenged != public {
			t.Errorf("public=%v: challenged = %v", public, challenged)
		}
		if public && !m.createdChallenge.GetPublicComputer() {
			t.Error("the challenge does not carry the public-computer choice")
		}
	}
}

// VerifyMfa completes the sign-in its challenge started, as it started it: a
// public challenge gets a public session (short lifetime, recorded, echoed)
// and does NOT trust the device although the second factor passed; the
// request has no say. A normal challenge still trusts it.
func TestVerifyMfa_PublicComputerComesFromTheChallenge(t *testing.T) {
	for _, public := range []bool{false, true} {
		m := &mfaMock{userEmail: "a@b.c"}
		h := newMfaHandler(m)
		h.TwoFactorTOTP = false
		h.SessionTokenTTLSeconds, h.PublicSessionTTLSeconds = 86400, 1800
		log := keepHistory(h)
		ctx := withJKT(context.Background(), testJKT)
		if _, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, public); !challenged {
			t.Fatal("expected a challenge")
		}
		resp, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: m.createdChallenge.GetCode()})
		if err != nil {
			t.Fatalf("public=%v: verify: %v", public, err)
		}
		if resp.GetPublicComputer() != public || m.issuedReq.GetPublicComputer() != public {
			t.Errorf("public=%v: response %v, session %v", public, resp.GetPublicComputer(), m.issuedReq.GetPublicComputer())
		}
		if trusted := m.trustedDevice != nil; trusted == public {
			t.Errorf("public=%v: the device trusted = %v", public, trusted)
		}
		wantTTL := 24 * time.Hour
		if public {
			wantTTL = 30 * time.Minute
		}
		if !within(m.issuedReq.GetExpiresAt(), wantTTL) {
			t.Errorf("public=%v: expires in %v, want %v", public, time.Until(m.issuedReq.GetExpiresAt().AsTime()), wantTTL)
		}
		if n := len(log.rows); n == 0 || log.rows[n-1].GetPublicComputer() != public {
			t.Errorf("public=%v: history %v", public, log.rows)
		}
	}
}

// OAuthExchange takes the choice at the exchange (the mint): public lifetime,
// recorded, echoed. It never trusts the device either way.
func TestOAuthExchange_PublicComputer(t *testing.T) {
	h, m, state := exchangeHandler(t)
	h.SessionTokenTTLSeconds, h.PublicSessionTTLSeconds = 86400, 600
	cb, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := h.OAuthExchange(mintCtx(), &pb.OAuthExchangeReq{Code: cb.GetCode(), CodeVerifier: validVerifier(), PublicComputer: true})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !ex.GetPublicComputer() || !m.issuedReq.GetPublicComputer() {
		t.Errorf("response %v, session %v, want both public", ex.GetPublicComputer(), m.issuedReq.GetPublicComputer())
	}
	if !within(m.issuedReq.GetExpiresAt(), 10*time.Minute) {
		t.Errorf("expires in %v, want the public lifetime", time.Until(m.issuedReq.GetExpiresAt().AsTime()))
	}
	if m.trustedDevice {
		t.Error("the OAuth exchange trusted the device")
	}
}

// SignUp (when it issues a session) and ConfirmSignUp (the confirming
// request's own choice) honour it too.
func TestSignUpAndConfirm_PublicComputer(t *testing.T) {
	pinConsoleActivation(t)
	s := newRoundTripStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings(), PublicSessionTTLSeconds: 900}
	resp, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "a@example.com", Password: devicePassword, PublicComputer: true})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetPublicComputer() || !s.issued[0].GetPublicComputer() || !within(s.issued[0].GetExpiresAt(), 15*time.Minute) {
		t.Errorf("SignUp: response %v, session %+v", resp.GetPublicComputer(), s.issued[0])
	}

	ch, cs := confirmHandler(t)
	ch.PublicSessionTTLSeconds = 900
	parked, err := ch.SignUp(mintCtx(), &pb.SignUpReq{Email: "b@example.com", Password: "pw-b"})
	if err != nil {
		t.Fatal(err)
	}
	done, err := ch.ConfirmSignUp(mintCtx(), &pb.ConfirmSignUpReq{PendingId: parked.GetPendingId(), Code: cs.codes[parked.GetPendingId()], PublicComputer: true})
	if err != nil {
		t.Fatal(err)
	}
	if !done.GetPublicComputer() || !cs.issued[0].GetPublicComputer() || !within(cs.issued[0].GetExpiresAt(), 15*time.Minute) {
		t.Errorf("ConfirmSignUp: response %v, session %+v", done.GetPublicComputer(), cs.issued[0])
	}
}

// The public lifetime: its default is 8 hours; it is never longer than the
// session lifetime (capped at use, refused at boot); a normal session keeps
// the normal one.
func TestPublicSessionTTL(t *testing.T) {
	h := &AuthServiceHandler{}
	if !within(h.sessionExpiry(true), 8*time.Hour) || !within(h.sessionExpiry(false), 30*24*time.Hour) {
		t.Errorf("defaults: public %v, normal %v", time.Until(h.sessionExpiry(true).AsTime()), time.Until(h.sessionExpiry(false).AsTime()))
	}
	h = &AuthServiceHandler{SessionTokenTTLSeconds: 3600}
	if !within(h.sessionExpiry(true), time.Hour) {
		t.Errorf("the public default outlived a one-hour session lifetime: %v", time.Until(h.sessionExpiry(true).AsTime()))
	}
	if err := ValidateConfig(&AuthServiceHandler{SessionTokenTTLSeconds: 3600, PublicSessionTTLSeconds: 7200, DeliveryRecipient: testRecipient}); err == nil ||
		!strings.Contains(err.Error(), "public_session_ttl_seconds=7200") {
		t.Errorf("a public lifetime longer than the session's was accepted: %v", err)
	}
	if err := ValidateConfig(&AuthServiceHandler{PublicSessionTTLSeconds: 28800, DeliveryRecipient: testRecipient}); err != nil {
		t.Errorf("the defaults were refused: %v", err)
	}
	if err := ValidateConfig(&AuthServiceHandler{SessionTokenTTLSeconds: 3600, PublicSessionTTLSeconds: 3600, DeliveryRecipient: testRecipient}); err != nil {
		t.Errorf("an equal lifetime was refused: %v", err)
	}
}

// The bundle fills an unset knob with its manifest default, so whatever
// plugin.yaml declares for public_session_ttl_seconds is what every
// deployment that does not set it boots with. It must boot with a session
// lifetime shorter than 8 hours, and give a public session that lifetime.
func TestPublicSessionTTL_TheManifestDefaultBootsWithShortSessions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^  - name: public_session_ttl_seconds\n    type: int\n    default: "(-?\d+)"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("no public_session_ttl_seconds default in plugin.yaml")
	}
	def, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	h := &AuthServiceHandler{SessionTokenTTLSeconds: 3600, PublicSessionTTLSeconds: def, DeliveryRecipient: testRecipient}
	if err := ValidateConfig(h); err != nil {
		t.Fatalf("the manifest default %d fails the boot of a deployment with one-hour sessions: %v", def, err)
	}
	if !within(h.sessionExpiry(true), time.Hour) {
		t.Errorf("a public session expires in %v, want the one-hour session lifetime", time.Until(h.sessionExpiry(true).AsTime()))
	}
}

// device/cli-own-device: the CLI session is bound to the key of the CLI that
// redeems the code — not to the browser that approved it — and the
// approving browser's device is recorded on the code and then on the CLI
// session, where the Sessions detail shows it.
func TestCliLogin_RecordsTheApproversDeviceAndBindsTheCLIsOwn(t *testing.T) {
	m := newCliMock()
	m.sessionDevice = "dev-browser"
	h := newCliHandler(m)
	verifier := validVerifier()
	authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(verifier), RedirectUri: "http://127.0.0.1:54123/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.codes[sha256Hex(authz.GetCode())].approvedBy; got != "dev-browser" {
		t.Errorf("the code records approver %q, want the approving session's device", got)
	}
	// The CLI signs with its own key (otherJKT), not the browser's.
	if _, err := h.CliToken(withJKT(context.Background(), otherJKT), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier}); err != nil {
		t.Fatal(err)
	}
	if want := "dev-" + otherJKT[:8]; m.issuedReq.GetDeviceId() != want {
		t.Errorf("the CLI session is bound to %q, want the CLI's own device %q", m.issuedReq.GetDeviceId(), want)
	}
	if m.issuedReq.GetApprovedByDeviceId() != "dev-browser" {
		t.Errorf("the CLI session records approver %q, want dev-browser", m.issuedReq.GetApprovedByDeviceId())
	}
	if m.issuedReq.GetPublicComputer() {
		t.Error("a CLI session was marked public")
	}
	// Every other mint records no approver.
	ms, hs := newSignInStore(t, "u1")
	noSecondFactor(t)
	if _, err := hs.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatal(err)
	}
	if ms.issued[0].GetApprovedByDeviceId() != "" {
		t.Errorf("a password session records approver %q", ms.issued[0].GetApprovedByDeviceId())
	}
}

// A code approved by a browser device that is revoked before the CLI redeems
// it mints nothing: the opaque refusal, recorded as REFUSED. A failed read of
// the approver refuses too. A live approver mints (above).
func TestCliToken_RefusesACodeWhoseApproverWasRevoked(t *testing.T) {
	for name, arrange := range map[string]func(m *cliMock){
		"revoked":     func(m *cliMock) { m.approverRevoked = map[string]bool{"dev-browser": true} },
		"read fails":  func(m *cliMock) { m.approverErr = status.Error(codes.Unavailable, "db down") },
		"no such row": func(m *cliMock) { m.approverErr = status.Error(codes.NotFound, "no rows") },
	} {
		m := newCliMock()
		m.sessionDevice = "dev-browser"
		h := newCliHandler(m)
		log := keepHistory(h)
		verifier := validVerifier()
		authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(verifier), RedirectUri: "http://127.0.0.1:54123/cb"})
		if err != nil {
			t.Fatal(err)
		}
		arrange(m)
		_, err = h.CliToken(withJKT(context.Background(), otherJKT), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
		if err == nil {
			t.Fatalf("%s: a code of a revoked approver minted a session", name)
		}
		if m.issuedReq != nil {
			t.Errorf("%s: a session was issued", name)
		}
		want := status.Code(err)
		if name == "read fails" {
			if want != codes.Unavailable {
				t.Errorf("%s: an outage answered %v", name, err)
			}
		} else if want != codes.Unauthenticated || len(status.Convert(err).Details()) != 0 {
			t.Errorf("%s: answered %v, want the opaque refusal", name, err)
		}
		if name == "revoked" && (len(log.rows) != 1 || log.rows[0].GetOutcome() != pb.SignInOutcome_SIGN_IN_OUTCOME_REFUSED) {
			t.Errorf("%s: history %v, want one REFUSED row", name, log.rows)
		}
	}
}

// The statements carry the new columns: the session's public flag and
// approver, the challenge's and the history's public flag, the code's
// approver from the approving session's row.
func TestPublicComputerAndApproverStatements(t *testing.T) {
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	for _, c := range []struct{ name, body, want string }{
		{"IssueToken", m["IssueToken"], `public_computer = :public_computer, `},
		{"IssueToken", m["IssueToken"], `approved_by_device_id = :approved_by_device_id `},
		{"CreateMfaChallenge", m["CreateMfaChallenge"], `public_computer = :public_computer `},
		{"RecordSignInEvent", m["RecordSignInEvent"], `public_computer = :public_computer `},
		{"CreateCliAuthCode", m["CreateCliAuthCode"], `approved_by_device_id = :approved_by_device_id `},
		{"ConsumeCliAuthCode", m["ConsumeCliAuthCode"], `session_expires_at, approved_by_device_id`},
		{"GetMfaChallenge", q["GetMfaChallenge"], `c.public_computer AS challenge.public_computer`},
		{"GetLiveSessionExpiry", q["GetLiveSessionExpiry"], `t.device_id AS device_id`},
		{"GetCliApproverRevocation", q["GetCliApproverRevocation"], `SELECT d.id AS device_id, d.revoked_at AS revoked_at FROM @module.Device d WHERE d.id = :device_id`},
		{"GetSignInEvent", q["GetSignInEvent"], `e.public_computer AS public_computer`},
		{"ListUserSignInEvents", q["ListUserSignInEvents"], `e.public_computer AS public_computer`},
	} {
		if !strings.Contains(c.body, c.want) {
			t.Errorf("%s lacks %s:\n%s", c.name, c.want, c.body)
		}
	}
}
