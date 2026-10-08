package handlers

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// enrolled sets up a CONFIRMED authenticator through the real handlers and
// returns its seed and the recovery codes the confirmation handed out.
func enrolled(t *testing.T, h *AuthServiceHandler, ctx context.Context) (string, []string) {
	t.Helper()
	e, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, _ := totp.Code(e.GetSecret(), time.Now())
	c, err := h.ConfirmTotp(ctx, &pb.ConfirmTotpReq{Code: code})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return e.GetSecret(), c.GetRecoveryCodes()
}

// RFC 6238 §5.2: a verifier must not accept the second attempt of the same
// OTP. Before last_step, a code verified for its whole ~90-second window, so
// one read over a shoulder or out of a phishing page signed in a second time.
func TestTotp_ACodeIsAcceptedOnce(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	seed, _ := enrolled(t, h, ctx)
	code := nextCode(t, seed)
	if !h.verifyMfaCode(ctx, "u1", "", code) {
		t.Fatal("a fresh code was refused")
	}
	if h.verifyMfaCode(ctx, "u1", "", code) {
		t.Error("the same code was accepted twice")
	}
	// And the confirm's own code cannot be replayed into a sign-in.
	confirmCode, _ := totp.Code(seed, time.Now())
	if h.verifyMfaCode(ctx, "u1", "", confirmCode) {
		t.Error("the code that confirmed the authenticator signed in afterwards")
	}
}

// Two requests presenting one code at once: the claim, not a read-then-write,
// decides — exactly one of them is accepted.
func TestTotp_ConcurrentReuseIsAcceptedOnce(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	seed, _ := enrolled(t, h, ctx)
	code := nextCode(t, seed)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.verifyMfaCode(ctx, "u1", "", code) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Errorf("one code accepted %d times", accepted)
	}
}

// A claim the store does not answer is not an acceptance.
func TestTotp_AnUnansweredClaimFailsClosed(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	seed, _ := enrolled(t, h, ctx)
	m.claimErr = status.Error(codes.Unavailable, "store down")
	if h.verifyMfaCode(ctx, "u1", "", nextCode(t, seed)) {
		t.Error("a code whose step could not be claimed was accepted")
	}
}

func TestConfirmTotp_HandsOutTenRecoveryCodesStoredHashed(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	_, rc := enrolled(t, h, ctx)
	if len(rc) != recoveryCodeCount {
		t.Fatalf("%d recovery codes, want %d", len(rc), recoveryCodeCount)
	}
	shape := regexp.MustCompile(`^[` + recoveryAlphabet + `]{5}-[` + recoveryAlphabet + `]{5}$`)
	seen := map[string]bool{}
	for _, c := range rc {
		if !shape.MatchString(c) || seen[c] {
			t.Errorf("recovery code %q: malformed or repeated", c)
		}
		seen[c] = true
		if _, plain := m.recovery[normaliseRecoveryCode(c)]; plain {
			t.Errorf("recovery code %q is stored in the clear", c)
		}
		if _, ok := m.recovery[recoveryCodeHash(normaliseRecoveryCode(c))]; !ok {
			t.Errorf("recovery code %q is not stored", c)
		}
	}
	st, err := h.GetMfaStatus(ctx, &pb.GetMfaStatusReq{})
	if err != nil || st.GetRecoveryCodesRemaining() != recoveryCodeCount {
		t.Errorf("status: %+v, %v", st, err)
	}
}

// A recovery code signs in — typed any case, dash or not — once.
func TestVerifyMfa_ARecoveryCodeSignsInOnce(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	_, rc := enrolled(t, h, ctx)
	typed := strings.ToUpper(strings.ReplaceAll(rc[0], "-", " "))
	if _, ch, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1"}, "", false); !ch {
		t.Fatal("expected challenge")
	}
	if v, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: typed}); err != nil || v.GetToken() == "" {
		t.Fatalf("a recovery code did not sign in: %v", err)
	}
	if _, ch, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1"}, "", false); !ch {
		t.Fatal("expected challenge")
	}
	if _, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: rc[0]}); err == nil {
		t.Error("a spent recovery code signed in again")
	}
	st, _ := h.GetMfaStatus(ctx, &pb.GetMfaStatusReq{})
	if st.GetRecoveryCodesRemaining() != recoveryCodeCount-1 {
		t.Errorf("remaining = %d, want %d", st.GetRecoveryCodesRemaining(), recoveryCodeCount-1)
	}
}

// Re-enrolling over a confirmed authenticator replaces it — switching 2FA
// off until the new one is confirmed — so it takes the same proof DisableTotp
// does. A lost phone is a recovery code.
func TestEnrollTotp_ReplacingAConfirmedAuthenticatorTakesACode(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	_, rc := enrolled(t, h, ctx)
	m.deletedTotp = false
	if _, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("re-enrolling with no code: %v, want Unauthenticated", err)
	}
	if _, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{Code: "000000"}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("re-enrolling with a wrong code: %v, want Unauthenticated", err)
	}
	if m.deletedTotp {
		t.Fatal("the confirmed authenticator was replaced without proof")
	}
	if _, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{Code: rc[1]}); err != nil {
		t.Errorf("re-enrolling with a recovery code (lost phone): %v", err)
	}
}

func TestDisableTotp_TakesARecoveryCodeAndDropsTheSet(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	_, rc := enrolled(t, h, ctx)
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: rc[2]}); err != nil {
		t.Fatalf("disable with a recovery code: %v", err)
	}
	if !m.deletedTotp || m.recovery != nil {
		t.Errorf("deleted=%v recovery=%v — the authenticator and its codes go together", m.deletedTotp, m.recovery)
	}
}

func TestGenerateRecoveryCodes_ReplacesTheSetBehindTheStepUp(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	if _, err := h.GenerateRecoveryCodes(ctx, &pb.GenerateRecoveryCodesReq{}); status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeTotpNotEnrolled {
		t.Errorf("without an authenticator: %v, want FailedPrecondition/%s", err, CodeTotpNotEnrolled)
	}
	seed, old := enrolled(t, h, ctx)
	if _, err := h.GenerateRecoveryCodes(ctx, &pb.GenerateRecoveryCodesReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("without the step-up: %v, want Unauthenticated", err)
	}
	fresh, err := h.GenerateRecoveryCodes(ctx, &pb.GenerateRecoveryCodesReq{Code: nextCode(t, seed)})
	if err != nil || len(fresh.GetRecoveryCodes()) != recoveryCodeCount {
		t.Fatalf("regenerate: %v (%d codes)", err, len(fresh.GetRecoveryCodes()))
	}
	if h.acceptRecoveryCode(ctx, "u1", old[3]) {
		t.Error("a code from the replaced set still works")
	}
	if !h.acceptRecoveryCode(ctx, "u1", fresh.GetRecoveryCodes()[0]) {
		t.Error("a code from the new set does not work")
	}
}

// The enrolment answer carries the QR code itself, an SVG of the otpauth URI.
func TestEnrollTotp_ReturnsTheQrCodeAsSvg(t *testing.T) {
	h := newMfaHandler(&mfaMock{userEmail: "a@b.c"})
	e, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.GetQrSvg(), "<svg ") || !strings.Contains(e.GetQrSvg(), `<path fill="#000" d="M`) {
		t.Errorf("qr_svg = %.80q…", e.GetQrSvg())
	}
}
