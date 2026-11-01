package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// device/sign-in-history: every sign-in attempt on every mint path appends
// exactly one SignInEvent — success and failure, refusals before any account
// lookup included — and the row changes nothing the caller gets.

// ── the history store ─────────────────────────────────────────

// historyLog is the SignInEvent table as RecordSignInEvent fills it, with the
// transaction each row was written in.
type historyLog struct {
	rows  []*pb.RecordSignInEventReq
	txIDs []string // the w17-tx-id a row was written under; "" = none
	// err fails every write; errInTx only a write inside a transaction.
	err     error
	errInTx error
	// block stalls every write until its context ends (a hung store).
	block bool
}

// historyMutation keeps the history in front of any test store.
type historyMutation struct {
	pb.AuthMutationClient
	log *historyLog
}

func (historyMutation) keepsSignInHistory() {}

func (m historyMutation) RecordSignInEvent(ctx context.Context, in *pb.RecordSignInEventReq, _ ...grpc.CallOption) (*pb.RecordSignInEventResp, error) {
	tx := outgoingTxID(ctx)
	if m.log.block {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
			return nil, errors.New("the write was never cut short")
		}
	}
	if m.log.err != nil {
		return nil, m.log.err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if tx != "" && m.log.errInTx != nil {
		return nil, m.log.errInTx
	}
	m.log.rows = append(m.log.rows, proto.Clone(in).(*pb.RecordSignInEventReq))
	m.log.txIDs = append(m.log.txIDs, tx)
	return &pb.RecordSignInEventResp{Id: fmt.Sprintf("sie-%d", len(m.log.rows))}, nil
}

// keepHistory puts a history store in front of h's mutation client.
func keepHistory(h *AuthServiceHandler) *historyLog {
	log := &historyLog{}
	h.Mutation = historyMutation{AuthMutationClient: h.Mutation, log: log}
	return log
}

func outgoingTxID(ctx context.Context) string {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("w17-tx-id"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// signInEventOf is the row a RecordSignInEvent request inserts.
func signInEventOf(in *pb.RecordSignInEventReq) *pb.SignInEvent {
	return &pb.SignInEvent{
		CreatedAt: timestamppb.Now(), UserId: in.GetUserId(), Address: in.GetAddress(),
		DeviceId: in.GetDeviceId(), Thumbprint: in.GetThumbprint(), Ip: in.GetIp(),
		UserAgent: in.GetUserAgent(), Method: in.GetMethod(), Outcome: in.GetOutcome(),
		PublicComputer: in.GetPublicComputer(),
	}
}

// The client a mint request comes from, as the gateway forwards it.
const (
	historyUA = "Mozilla/5.0 Firefox/130"
	historyIP = "203.0.113.9"
)

// historyCtx is a mint request from the device jkt ("" = no proof) with the
// forwarded user agent and client address.
func historyCtx(jkt string) context.Context {
	md := metadata.Pairs(forwardedUserAgentMetadataKey, historyUA, clientIPMetadataKey, historyIP+", 10.0.0.1")
	if jkt != "" {
		md.Set(dpopJKTKey, jkt)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

// want is what one history row must say.
type want struct {
	method  pb.SignInMethod
	outcome pb.SignInOutcome
	user    string
	address string
	device  string
	thumb   string
}

// one asserts the log holds exactly one row, and that it is w (with the
// client of historyCtx).
func (l *historyLog) one(t *testing.T, what string, w want) *pb.RecordSignInEventReq {
	t.Helper()
	if len(l.rows) != 1 {
		t.Fatalf("%s: %d history rows %v, want exactly one", what, len(l.rows), l.rows)
	}
	r := l.rows[0]
	got := want{r.GetMethod(), r.GetOutcome(), r.GetUserId(), r.GetAddress(), r.GetDeviceId(), r.GetThumbprint()}
	if got != w {
		t.Errorf("%s: row = %+v,\n want %+v", what, got, w)
	}
	if r.GetIp() != historyIP || r.GetUserAgent() != historyUA {
		t.Errorf("%s: row client = %q / %q, want %q / %q", what, r.GetIp(), r.GetUserAgent(), historyIP, historyUA)
	}
	return r
}

// sameAnswer asserts two calls answered byte-identically: the same status,
// details included, or both no error.
func sameAnswer(t *testing.T, what string, got, before error) {
	t.Helper()
	if (got == nil) != (before == nil) {
		t.Fatalf("%s: err = %v, before the history %v", what, got, before)
	}
	if got == nil {
		return
	}
	if !proto.Equal(status.Convert(got).Proto(), status.Convert(before).Proto()) {
		t.Errorf("%s: the answer changed:\n got    %v\n before %v", what, status.Convert(got).Proto(), status.Convert(before).Proto())
	}
}

// ── SignIn ────────────────────────────────────────────────────

// lookupOutage answers every account lookup with an outage.
type lookupOutage struct{ *signInStore }

func (lookupOutage) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}

// Every outcome of a password sign-in writes one row naming what the attempt
// reached, and the caller's answer is the one it got before the history
// existed — also when the history cannot be written.
func TestSignInHistory_SignIn_EveryOutcomeWritesOneRow(t *testing.T) {
	const pw = devicePassword
	setGate := func(t *testing.T, p *func(*pb.User) error, f func(*pb.User) error) {
		saved := *p
		*p = f
		t.Cleanup(func() { *p = saved })
	}
	setMfa := func(t *testing.T, resp *pb.SignInResp, challenged bool, err error) {
		saved := signInMfaGate
		signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool, bool) (*pb.SignInResp, bool, error) {
			return resp, challenged, err
		}
		t.Cleanup(func() { signInMfaGate = saved })
	}
	for _, c := range []struct {
		name     string
		jkt      string
		email    string
		password string
		setup    func(t *testing.T, m *signInStore, h *AuthServiceHandler)
		want     want
	}{
		{name: "ok", jkt: testJKT, email: "  U1@Example.com ", password: pw,
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK, user: "u1", device: "dev-1", thumb: testJKT}},
		{name: "wrong password", jkt: testJKT, email: "u1@example.com", password: "nope",
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_PASSWORD, user: "u1", thumb: testJKT}},
		{name: "unknown address", jkt: testJKT, email: "Nobody@Example.com", password: pw,
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_UNKNOWN_ACCOUNT, address: "nobody@example.com", thumb: testJKT}},
		{name: "no proof", email: "u1@example.com", password: pw,
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_PROOF_REQUIRED}},
		{name: "revoked device", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(_ *testing.T, m *signInStore, _ *AuthServiceHandler) {
				m.put("u1", testJKT, &pb.Device{Id: "dev-r", RevokedAt: timestamppb.Now()})
			},
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_REVOKED, user: "u1", device: "dev-r", thumb: testJKT}},
		{name: "disabled", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(t *testing.T, _ *signInStore, _ *AuthServiceHandler) {
				setGate(t, &signInDisabledGate, func(*pb.User) error { return errAuthnUserDisabled })
			},
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_ACCOUNT_DISABLED, user: "u1", thumb: testJKT}},
		{name: "machine account", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(t *testing.T, _ *signInStore, _ *AuthServiceHandler) {
				setGate(t, &signInBotGate, func(*pb.User) error { return errAuthnBotNoPassword })
			},
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_MACHINE_ACCOUNT, user: "u1", thumb: testJKT}},
		{name: "second factor asked", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(t *testing.T, _ *signInStore, _ *AuthServiceHandler) {
				setMfa(t, &pb.SignInResp{MfaRequired: true, ChallengeId: "ch-1"}, true, nil)
			},
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_MFA_REQUIRED, user: "u1", device: "dev-1", thumb: testJKT}},
		{name: "challenge cap spent", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(t *testing.T, _ *signInStore, _ *AuthServiceHandler) {
				setMfa(t, nil, false, errMfaChallengeBudget)
			},
			want: want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_RATE_LIMITED, user: "u1", device: "dev-1", thumb: testJKT}},
		{name: "store outage", jkt: testJKT, email: "u1@example.com", password: pw,
			setup: func(_ *testing.T, m *signInStore, h *AuthServiceHandler) { h.Query = lookupOutage{m} },
			want:  want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR, thumb: testJKT}},
	} {
		t.Run(c.name, func(t *testing.T) {
			noSecondFactor(t)
			saved := signInDummyVerify
			signInDummyVerify = func(*AuthServiceHandler, string) {}
			t.Cleanup(func() { signInDummyVerify = saved })

			run := func(history bool, writeErr error) (*historyLog, *pb.SignInResp, error) {
				m, h := newSignInStore(t, "u1")
				if c.setup != nil {
					c.setup(t, m, h)
				}
				var log *historyLog
				if history {
					log = keepHistory(h)
					log.err = writeErr
				}
				resp, err := h.SignIn(historyCtx(c.jkt), &pb.SignInReq{Email: c.email, Password: c.password})
				return log, resp, err
			}
			_, beforeResp, before := run(false, nil)
			log, resp, err := run(true, nil)
			w := c.want
			w.method = pb.SignInMethod_SIGN_IN_METHOD_PASSWORD
			if w.address == "" {
				w.address = strings.ToLower(strings.TrimSpace(c.email))
			}
			log.one(t, c.name, w)
			sameAnswer(t, c.name, err, before)
			if resp.GetMfaRequired() != beforeResp.GetMfaRequired() || (resp.GetToken() == "") != (beforeResp.GetToken() == "") {
				t.Errorf("%s: response %+v, before %+v", c.name, resp, beforeResp)
			}
			if w.outcome == pb.SignInOutcome_SIGN_IN_OUTCOME_OK {
				return
			}
			// A refusal whose row cannot be written is still the same refusal.
			_, _, failed := run(true, status.Error(codes.Unavailable, "history down"))
			sameAnswer(t, c.name+", history write failing", failed, before)
		})
	}
}

// The success row is written in the transaction that mints the session; a
// history write that fails there fails the sign-in — no session exists
// without its row — and the failure is recorded instead, on its own.
func TestSignInHistory_SignIn_TheSuccessRowIsInTheSessionsTransaction(t *testing.T) {
	noSecondFactor(t)
	m, h := newSignInStore(t, "u1")
	tx := &recordingDistTx{}
	h.DistTx = tx
	log := keepHistory(h)
	resp, err := h.SignIn(historyCtx(testJKT), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if err != nil || resp.GetToken() == "" {
		t.Fatalf("SignIn: %+v, %v", resp, err)
	}
	log.one(t, "ok", want{pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, pb.SignInOutcome_SIGN_IN_OUTCOME_OK, "u1", "u1@example.com", "dev-1", testJKT})
	if log.txIDs[0] != fakeTxID || tx.settled() != "committed" || len(m.issued) != 1 {
		t.Errorf("row tx %q, transaction %s, issued %d: want the row and the token in one committed transaction", log.txIDs[0], tx.settled(), len(m.issued))
	}

	m, h = newSignInStore(t, "u1")
	tx = &recordingDistTx{}
	h.DistTx = tx
	log = keepHistory(h)
	log.errInTx = status.Error(codes.Unavailable, "history down")
	resp, err = h.SignIn(historyCtx(testJKT), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if err == nil || resp.GetToken() != "" {
		t.Fatalf("a session was handed out without its history row: %+v", resp)
	}
	if tx.settled() != "rolled back" {
		t.Errorf("transaction %s, want rolled back (the token with it)", tx.settled())
	}
	log.one(t, "history failing in the transaction", want{pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR, "u1", "u1@example.com", "dev-1", testJKT})
	if log.txIDs[0] != "" {
		t.Errorf("the failure row was written in the rolled-back transaction %q", log.txIDs[0])
	}
	if len(m.trusted) != 0 {
		t.Error("a failed sign-in renewed device trust")
	}
}

// ── the other mint paths ──────────────────────────────────────

// device/no-unbound-credential still holds: without a proof every mint path
// refuses before it spends anything — and writes the one history row of the
// refused attempt, nothing else (the store panics on any other call).
func TestSignInHistory_EveryMintPathRecordsAProoflessAttempt(t *testing.T) {
	savedConfirm := signUpConfirmation
	signUpConfirmation = nil
	t.Cleanup(func() { signUpConfirmation = savedConfirm })

	ctx := historyCtx("")
	for name, c := range map[string]struct {
		method pb.SignInMethod
		call   func(h *AuthServiceHandler) error
	}{
		"SignIn": {pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, func(h *AuthServiceHandler) error {
			_, err := h.SignIn(ctx, &pb.SignInReq{Email: "A@example.com", Password: devicePassword})
			return err
		}},
		"SignUp": {pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP, func(h *AuthServiceHandler) error {
			_, err := h.SignUp(ctx, &pb.SignUpReq{Email: "A@example.com", Password: devicePassword})
			return err
		}},
		"ConfirmSignUp": {pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP_CONFIRM, func(h *AuthServiceHandler) error {
			_, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: "p1", Code: "ABCD2345"})
			return err
		}},
		"VerifyMfa": {pb.SignInMethod_SIGN_IN_METHOD_MFA, func(h *AuthServiceHandler) error {
			_, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "c1", Code: "123456"})
			return err
		}},
		"OAuthExchange": {pb.SignInMethod_SIGN_IN_METHOD_OAUTH, func(h *AuthServiceHandler) error {
			_, err := h.OAuthExchange(ctx, &pb.OAuthExchangeReq{Code: "code", CodeVerifier: strings.Repeat("v", 43)})
			return err
		}},
		"CliToken": {pb.SignInMethod_SIGN_IN_METHOD_CLI, func(h *AuthServiceHandler) error {
			_, err := h.CliToken(ctx, &pb.CliTokenReq{Code: "code", CodeVerifier: strings.Repeat("v", 43)})
			return err
		}},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s reached storage beyond its history row without a proof: %v", name, r)
				}
			}()
			h := &AuthServiceHandler{Query: nothingStore{}, Mutation: nothingStore{}, PasswordHash: testPasswordSettings()}
			log := keepHistory(h)
			err := c.call(h)
			if detailOf(t, err).GetCode() != CodeDeviceProofRequired {
				t.Errorf("%s: err = %v, want %s", name, err, CodeDeviceProofRequired)
			}
			w := want{method: c.method, outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_PROOF_REQUIRED}
			if name == "SignIn" || name == "SignUp" {
				w.address = "a@example.com"
			}
			log.one(t, name, w)
		}()
	}
}

// SignUp that issues a session: one row per attempt, the gates' refusals
// included; the success row in the registration's transaction. A parked
// registration (sign_up_confirmation) signs nobody in and writes none.
func TestSignInHistory_SignUp(t *testing.T) {
	pinConsoleActivation(t)
	s := newRoundTripStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	tx := &recordingDistTx{}
	h.DistTx = tx
	log := keepHistory(h)
	resp, err := h.SignUp(historyCtx(testJKT), &pb.SignUpReq{Email: "New@Example.com", Password: devicePassword})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	log.one(t, "ok", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP, pb.SignInOutcome_SIGN_IN_OUTCOME_OK, resp.GetUserId(), "new@example.com", "dev-" + testJKT[:8], testJKT})
	if log.txIDs[0] != fakeTxID || tx.settled() != "committed" {
		t.Errorf("row tx %q, transaction %s: want the row in the registration's committed transaction", log.txIDs[0], tx.settled())
	}

	// A refusal by a gate (the reserved domain), before any write.
	h = &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	log = keepHistory(h)
	_, err = h.SignUp(historyCtx(testJKT), &pb.SignUpReq{Email: "x@erased.invalid", Password: devicePassword})
	if detailOf(t, err).GetCode() != CodeEmailInvalid {
		t.Fatalf("reserved domain: %v", err)
	}
	log.one(t, "reserved domain", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP, pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED, "", "x@erased.invalid", "", testJKT})

	// A failed history write in the transaction rolls the registration back:
	// the failure row names no account (the account was never committed).
	h = &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	tx = &recordingDistTx{}
	h.DistTx = tx
	log = keepHistory(h)
	log.errInTx = status.Error(codes.Unavailable, "history down")
	if _, err := h.SignUp(historyCtx(testJKT), &pb.SignUpReq{Email: "late@example.com", Password: devicePassword}); err == nil {
		t.Fatal("a registration's session was handed out without its history row")
	}
	log.one(t, "history failing", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP, pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR, "", "late@example.com", "", testJKT})
	if tx.settled() != "rolled back" {
		t.Errorf("transaction %s, want rolled back", tx.settled())
	}

	// Parked: no sign-in, no row.
	hc, _ := confirmHandler(t)
	log = keepHistory(hc)
	if _, err := hc.SignUp(historyCtx(testJKT), &pb.SignUpReq{Email: "p@example.com", Password: devicePassword}); err != nil {
		t.Fatalf("parked SignUp: %v", err)
	}
	if len(log.rows) != 0 {
		t.Errorf("a parked registration wrote history %v", log.rows)
	}
}

// ConfirmSignUp: a wrong code, the spent budget and the confirmation each
// write one row, naming the pending registration's address.
func TestSignInHistory_ConfirmSignUp(t *testing.T) {
	h, s := confirmHandler(t)
	parked, err := h.SignUp(withJKT(context.Background(), testJKT), &pb.SignUpReq{Email: "Ceo@Example.com", Password: "pw-owner"})
	if err != nil {
		t.Fatal(err)
	}
	pid := parked.GetPendingId()
	log := keepHistory(h)
	_, err = h.ConfirmSignUp(historyCtx(testJKT), &pb.ConfirmSignUpReq{PendingId: pid, Code: "00000000"})
	if !errors.Is(err, errSignUpConfirmInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	log.one(t, "wrong code", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP_CONFIRM, pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, "", "ceo@example.com", "", testJKT})

	log.rows = nil
	done, err := h.ConfirmSignUp(historyCtx(testJKT), &pb.ConfirmSignUpReq{PendingId: pid, Code: s.codes[pid]})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	log.one(t, "ok", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP_CONFIRM, pb.SignInOutcome_SIGN_IN_OUTCOME_OK, done.GetUserId(), "ceo@example.com", "dev-" + testJKT[:8], testJKT})

	// A second registration whose five guesses are spent: the sixth, even
	// with the right code, is TOO_MANY_ATTEMPTS.
	parked, err = h.SignUp(withJKT(context.Background(), testJKT), &pb.SignUpReq{Email: "two@example.com", Password: "pw-two"})
	if err != nil {
		t.Fatal(err)
	}
	pid = parked.GetPendingId()
	for i := 0; i < maxSignUpConfirmAttempts; i++ {
		_, _ = h.ConfirmSignUp(historyCtx(testJKT), &pb.ConfirmSignUpReq{PendingId: pid, Code: "00000000"})
	}
	log.rows = nil
	_, err = h.ConfirmSignUp(historyCtx(testJKT), &pb.ConfirmSignUpReq{PendingId: pid, Code: s.codes[pid]})
	if !errors.Is(err, errSignUpConfirmInvalid) {
		t.Fatalf("spent budget: %v", err)
	}
	log.one(t, "spent budget", want{pb.SignInMethod_SIGN_IN_METHOD_SIGN_UP_CONFIRM, pb.SignInOutcome_SIGN_IN_OUTCOME_TOO_MANY_ATTEMPTS, "", "two@example.com", "", testJKT})
}

// VerifyMfa: a wrong code, another key, a locked challenge and the completion
// each write one row for the challenged account.
func TestSignInHistory_VerifyMfa(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, challenged, _ := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); !challenged {
		t.Fatal("expected a challenge")
	}
	code := m.createdChallenge.GetCode()
	log := keepHistory(h)
	mfa := func(w want) want { w.method = pb.SignInMethod_SIGN_IN_METHOD_MFA; return w }

	_, err := h.VerifyMfa(historyCtx(testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"})
	if err == nil {
		t.Fatal("a wrong code passed")
	}
	log.one(t, "wrong code", mfa(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, user: "u1", thumb: testJKT}))

	log.rows = nil
	if _, err := h.VerifyMfa(historyCtx(otherJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); err == nil {
		t.Fatal("another key passed")
	}
	log.one(t, "another key", mfa(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OTHER_DEVICE, user: "u1", thumb: otherJKT}))

	log.rows = nil
	if _, err := h.VerifyMfa(historyCtx(testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); err != nil {
		t.Fatalf("completion: %v", err)
	}
	log.one(t, "ok", mfa(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK, user: "u1", device: "dev-" + testJKT[:8], thumb: testJKT}))

	// A challenge whose attempts are spent.
	m = &mfaMock{chUserID: "u1", chThumb: testJKT, chCreatedAt: timestamppb.Now(), chAttempts: maxMfaAttempts}
	h = newMfaHandler(m)
	h.TwoFactorTOTP = false
	log = keepHistory(h)
	if _, err := h.VerifyMfa(historyCtx(testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
		t.Fatal("a locked challenge passed")
	}
	log.one(t, "locked", mfa(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_TOO_MANY_ATTEMPTS, user: "u1", thumb: testJKT}))
}

// OAuthExchange: an unknown code, a wrong verifier and the sign-in each write
// one row; a sign-in names the provider's address.
func TestSignInHistory_OAuthExchange(t *testing.T) {
	h, _, state := exchangeHandler(t)
	log := keepHistory(h)
	oauth := func(w want) want { w.method = pb.SignInMethod_SIGN_IN_METHOD_OAUTH; return w }

	if _, err := h.OAuthExchange(historyCtx(testJKT), &pb.OAuthExchangeReq{Code: "nope", CodeVerifier: validVerifier()}); err == nil {
		t.Fatal("an unknown code was redeemed")
	}
	log.one(t, "unknown code", oauth(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, thumb: testJKT}))

	cb, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	log.rows = nil
	ex, err := h.OAuthExchange(historyCtx(testJKT), &pb.OAuthExchangeReq{Code: cb.GetCode(), CodeVerifier: validVerifier()})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	log.one(t, "ok", oauth(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK, user: ex.GetUserId(), address: "alice@idp.com", device: "dev-" + testJKT[:8], thumb: testJKT}))

	cb, err = h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	log.rows = nil
	if _, err := h.OAuthExchange(historyCtx(testJKT), &pb.OAuthExchangeReq{Code: cb.GetCode(), CodeVerifier: strings.Repeat("w", 43)}); err == nil {
		t.Fatal("a wrong verifier redeemed the code")
	}
	// The row names what the code names: the provider's address (this code
	// carries no account — the exchange resolves it, and a wrong verifier
	// stops it before that).
	log.one(t, "wrong verifier", oauth(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, address: "alice@idp.com", thumb: testJKT}))
}

// CliToken: an unknown code, a wrong verifier and the exchange each write one
// row.
func TestSignInHistory_CliToken(t *testing.T) {
	m := newCliMock()
	h := newCliHandler(m)
	verifier := validVerifier()
	log := keepHistory(h)
	cli := func(w want) want { w.method = pb.SignInMethod_SIGN_IN_METHOD_CLI; return w }

	if _, err := h.CliToken(historyCtx(testJKT), &pb.CliTokenReq{Code: "nope", CodeVerifier: verifier}); err == nil {
		t.Fatal("an unknown code was redeemed")
	}
	log.one(t, "unknown code", cli(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, thumb: testJKT}))

	authorize := func() string {
		a, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(verifier), RedirectUri: "http://127.0.0.1:54123/cb"})
		if err != nil {
			t.Fatal(err)
		}
		return a.GetCode()
	}
	log.rows = nil
	if _, err := h.CliToken(historyCtx(testJKT), &pb.CliTokenReq{Code: authorize(), CodeVerifier: strings.Repeat("w", 49)}); err == nil {
		t.Fatal("a wrong verifier redeemed the code")
	}
	log.one(t, "wrong verifier", cli(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, user: "user-1", thumb: testJKT}))

	log.rows = nil
	if _, err := h.CliToken(historyCtx(testJKT), &pb.CliTokenReq{Code: authorize(), CodeVerifier: verifier}); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	log.one(t, "ok", cli(want{outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK, user: "user-1", device: "dev-" + testJKT[:8], thumb: testJKT}))
}

// The outcome a refusal records is read off what the caller gets: each
// feature's sentinel, then the wire code, then the status code.
func TestSignInOutcome_ReadsTheRefusal(t *testing.T) {
	for _, c := range []struct {
		err  error
		want pb.SignInOutcome
	}{
		{UnauthenticatedSignIn(errAuthnPasswordMismatch), pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_PASSWORD},
		{Unauthenticated(errMfaAttemptsSpent), pb.SignInOutcome_SIGN_IN_OUTCOME_TOO_MANY_ATTEMPTS},
		{Unauthenticated(errCliClientAuthFailed), pb.SignInOutcome_SIGN_IN_OUTCOME_CLIENT_REFUSED},
		{oauthRefusal(errOAuthEmailUnverified), pb.SignInOutcome_SIGN_IN_OUTCOME_UNVERIFIED_EMAIL},
		{errSignUpNotInvited, pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED},
		{emailTaken(context.Background()), pb.SignInOutcome_SIGN_IN_OUTCOME_EMAIL_TAKEN},
		{deviceRevoked(context.Background()), pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_REVOKED},
		{Unauthenticated(errCliSessionNotLive), pb.SignInOutcome_SIGN_IN_OUTCOME_REFUSED},
		{Unauthenticated(status.Error(codes.Unavailable, "down")), pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR},
		{errors.New("unexpected"), pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR},
		// An outage the opaque refusal does not call one on the wire.
		{Unauthenticated(status.Error(codes.Unknown, "driver: bad connection")), pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR},
		{UnauthenticatedSignIn(status.Error(codes.Unknown, "driver: bad connection")), pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR},
	} {
		if got := signInOutcome(c.err); got != c.want {
			t.Errorf("signInOutcome(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// ── erasure ───────────────────────────────────────────────────

// An erasure pseudonymises the account's history and the attempts that named
// its address without reaching an account: the address becomes the
// placeholder, the client address and user agent are blanked. Every row
// stays; another account's rows and other addresses' are untouched.
func TestEraseUsers_PseudonymisesTheSignInHistory(t *testing.T) {
	s := aliceStore()
	s.users["u1"].email = "Alice@Example.com"
	s.addUser("u2", "bob@example.com")
	s.addUser("admin", "ops@example.com")
	h := eraseHandler(s)
	for _, r := range []*pb.RecordSignInEventReq{
		{UserId: "u1", Address: "alice@example.com", DeviceId: "d1", Thumbprint: testJKT, Ip: "198.51.100.1", UserAgent: "Firefox", Method: pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, Outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK},
		{UserId: "u1", Thumbprint: testJKT, Ip: "198.51.100.1", UserAgent: "Firefox", Method: pb.SignInMethod_SIGN_IN_METHOD_MFA, Outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE},
		// before the account existed (or a typo'd attempt at it): no account
		{Address: "alice@example.com", Ip: "198.51.100.2", UserAgent: "curl", Method: pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, Outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_UNKNOWN_ACCOUNT},
		{Address: "carol@example.com", Ip: "198.51.100.3", UserAgent: "curl", Method: pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, Outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_UNKNOWN_ACCOUNT},
		{UserId: "u2", Address: "bob@example.com", Ip: "198.51.100.4", UserAgent: "Safari", Method: pb.SignInMethod_SIGN_IN_METHOD_PASSWORD, Outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK},
	} {
		if _, err := s.RecordSignInEvent(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if len(s.signIns) != 5 {
		t.Fatalf("%d history rows after the erasure, want all 5 kept", len(s.signIns))
	}
	const placeholder = "erased-u1@erased.invalid"
	for i, wantAddr := range []string{placeholder, placeholder, placeholder, "carol@example.com", "bob@example.com"} {
		r := s.signIns[i]
		erased := wantAddr == placeholder
		if r.GetAddress() != wantAddr || (r.GetIp() == "") != erased || (r.GetUserAgent() == "") != erased {
			t.Errorf("row %d after erasure = %q %q %q, want address %q, client blanked: %v", i, r.GetAddress(), r.GetIp(), r.GetUserAgent(), wantAddr, erased)
		}
		if r.GetMethod() == pb.SignInMethod_SIGN_IN_METHOD_UNSPECIFIED || r.GetOutcome() == pb.SignInOutcome_SIGN_IN_OUTCOME_UNSPECIFIED {
			t.Errorf("row %d lost its method or outcome", i)
		}
	}
	if s.signIns[0].GetUserId() != "u1" || s.signIns[0].GetThumbprint() != testJKT || s.signIns[2].GetUserId() != "" {
		t.Error("the erasure rewrote a column that is not personal data")
	}
}

// ── the statements ────────────────────────────────────────────

// SignInEvent is append-only: the one INSERT is RecordSignInEvent, the one
// UPDATE is the erasure's (EraseSignInEvents), and it writes only the
// personal columns. Nothing else writes the table, in any proto.
func TestSignInEventIsAppendOnly(t *testing.T) {
	writes := 0
	reads := 0
	for rel, src := range authProtos(t) {
		for name, body := range rpcBodies(src) {
			for _, stmt := range dqlStatements(body) {
				if !strings.Contains(stmt, "@module.SignInEvent") {
					continue
				}
				head := strings.ToUpper(strings.Fields(stmt)[0])
				switch {
				case head == "SELECT":
					reads++
				case head == "INSERT" && name == "RecordSignInEvent":
					writes++
				case head == "UPDATE" && name == "EraseSignInEvents":
					writes++
					set := stmt[strings.Index(stmt, " SET ")+5 : strings.Index(stmt, " WHERE ")]
					for _, a := range strings.Split(set, ",") {
						col := strings.TrimSpace(strings.SplitN(a, "=", 2)[0])
						if col != "address" && col != "ip" && col != "user_agent" {
							t.Errorf("%s: the erasure rewrites %q — only address, ip and user_agent are personal", rel, col)
						}
					}
				default:
					t.Errorf("%s: %s writes SignInEvent (%q) — the table is append-only", rel, name, stmt)
				}
			}
		}
	}
	if writes != 2 || reads != 3 {
		t.Fatalf("found %d writes and %d reads of SignInEvent, want 2 and 3 — the guard is not looking at the statements", writes, reads)
	}

	ins := dqlStatements(mutationRPCBody(t, "RecordSignInEvent"))
	for _, col := range []string{"user_id = :user_id", "address = :address", "device_id = :device_id", "thumbprint = :thumbprint", "ip = :ip", "user_agent = :user_agent", "method = :method", "outcome = :outcome"} {
		if !strings.Contains(ins[0], col) {
			t.Errorf("RecordSignInEvent does not bind %q: %s", col, ins[0])
		}
	}
	erase := dqlStatements(mutationRPCBody(t, "EraseSignInEvents"))
	if len(erase) != 1 || !strings.Contains(erase[0], "WHERE user_id = :user_id OR (user_id IS NULL AND address = :email)") {
		t.Errorf("EraseSignInEvents = %v, want the account's rows and the account-less rows naming its address", erase)
	}
	for _, rpc := range []string{"ListUserSignInEvents"} {
		if q := queryRPCBody(t, rpc); !strings.Contains(q, "WHERE e.user_id = :user_id") {
			t.Errorf("%s reads beyond the account's own rows: %s", rpc, q)
		}
	}
}

// ── the person's own history ──────────────────────────────────

type ownHistoryQuery struct {
	pb.AuthQueryClient
	asked string
}

func (q *ownHistoryQuery) ListUserSignInEvents(_ context.Context, in *pb.ListUserSignInEventsReq, _ ...grpc.CallOption) (*pb.ListUserSignInEventsResp, error) {
	q.asked = in.GetUserId()
	return &pb.ListUserSignInEventsResp{Events: []*pb.SignInEvent{{Id: "e1", UserId: in.GetUserId()}}}, nil
}

// ListMySignInEvents reads the caller's own rows — the envelope's account,
// never a request field — and refuses a request with no caller.
func TestListMySignInEvents_ReadsOnlyTheCallersRows(t *testing.T) {
	q := &ownHistoryQuery{}
	h := &AuthServiceHandler{Query: q}
	resp, err := h.ListMySignInEvents(ctxWithCaller("u7"), &pb.ListMySignInEventsReq{})
	if err != nil || q.asked != "u7" || len(resp.GetEvents()) != 1 {
		t.Fatalf("ListMySignInEvents = %+v, %v (asked for %q), want u7's rows", resp, err, q.asked)
	}
	q.asked = ""
	if _, err := h.ListMySignInEvents(context.Background(), &pb.ListMySignInEventsReq{}); status.Code(err) != codes.Unauthenticated || q.asked != "" {
		t.Fatalf("no caller: %v (asked %q), want Unauthenticated before any read", err, q.asked)
	}
}

// ── events carry the device (device/events-carry-device) ─────

// deviceCallerCtx is an authenticated request whose envelope names the device
// jkt (AuthResp.device_id), as the gateway threads it.
func deviceCallerCtx(uid, sessionTokenID, jkt string) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: sessionTokenID, PermissionIds: []int32{5}, DeviceId: jkt})
	if err != nil {
		panic(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid, userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// emitCapture records the device thumbprint each event-emitting mutation was
// handed — the value its event_emit maps to the event's device_id (see
// TestEveryEventWithAUserCarriesTheDevice for the mapping).
type emitCapture struct {
	pb.AuthMutationClient
	thumbs map[string][]string
}

func capture(h *AuthServiceHandler) *emitCapture {
	c := &emitCapture{AuthMutationClient: h.Mutation, thumbs: map[string][]string{}}
	h.Mutation = c
	return c
}

func (c *emitCapture) note(rpc, thumb string) { c.thumbs[rpc] = append(c.thumbs[rpc], thumb) }

func (c *emitCapture) IssueToken(ctx context.Context, in *pb.IssueTokenReq, o ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	c.note("IssueToken", in.GetThumbprint())
	return c.AuthMutationClient.IssueToken(ctx, in, o...)
}

func (c *emitCapture) RevokeSessionToken(ctx context.Context, in *pb.RevokeSessionTokenReq, o ...grpc.CallOption) (*pb.RevokeSessionTokenResp, error) {
	c.note("RevokeSessionToken", in.GetThumbprint())
	return c.AuthMutationClient.RevokeSessionToken(ctx, in, o...)
}

func (c *emitCapture) RevokeUserToken(ctx context.Context, in *pb.RevokeUserTokenReq, o ...grpc.CallOption) (*pb.RevokeUserTokenResp, error) {
	c.note("RevokeUserToken", in.GetThumbprint())
	return c.AuthMutationClient.RevokeUserToken(ctx, in, o...)
}

func (c *emitCapture) CreateMfaChallenge(ctx context.Context, in *pb.CreateMfaChallengeReq, o ...grpc.CallOption) (*pb.CreateMfaChallengeResp, error) {
	c.note("CreateMfaChallenge", in.GetThumbprint())
	return c.AuthMutationClient.CreateMfaChallenge(ctx, in, o...)
}

func (c *emitCapture) ConsumeMfaChallenge(ctx context.Context, in *pb.ConsumeMfaChallengeReq, o ...grpc.CallOption) (*pb.ConsumeMfaChallengeResp, error) {
	c.note("ConsumeMfaChallenge", in.GetThumbprint())
	return c.AuthMutationClient.ConsumeMfaChallenge(ctx, in, o...)
}

func (c *emitCapture) ConsumeRecoveryCode(ctx context.Context, in *pb.ConsumeRecoveryCodeReq, o ...grpc.CallOption) (*pb.ConsumeRecoveryCodeResp, error) {
	c.note("ConsumeRecoveryCode", in.GetThumbprint())
	return c.AuthMutationClient.ConsumeRecoveryCode(ctx, in, o...)
}

func (c *emitCapture) CreateTotpSecret(ctx context.Context, in *pb.CreateTotpSecretReq, o ...grpc.CallOption) (*pb.CreateTotpSecretResp, error) {
	c.note("CreateTotpSecret", in.GetThumbprint())
	return c.AuthMutationClient.CreateTotpSecret(ctx, in, o...)
}

func (c *emitCapture) ConfirmTotpSecret(ctx context.Context, in *pb.ConfirmTotpSecretReq, o ...grpc.CallOption) (*pb.ConfirmTotpSecretResp, error) {
	c.note("ConfirmTotpSecret", in.GetThumbprint())
	return c.AuthMutationClient.ConfirmTotpSecret(ctx, in, o...)
}

func (c *emitCapture) RevokeTotpSecret(ctx context.Context, in *pb.RevokeTotpSecretReq, o ...grpc.CallOption) (*pb.RevokeTotpSecretResp, error) {
	c.note("RevokeTotpSecret", in.GetThumbprint())
	return c.AuthMutationClient.RevokeTotpSecret(ctx, in, o...)
}

// assertThumbs asserts every call of rpc was handed jkt, and there was one.
func (c *emitCapture) assertThumbs(t *testing.T, rpc, jkt string) {
	t.Helper()
	got := c.thumbs[rpc]
	if len(got) == 0 {
		t.Errorf("%s was not called", rpc)
	}
	for _, g := range got {
		if g != jkt {
			t.Errorf("%s carried device %q, want %q", rpc, g, jkt)
		}
	}
}

// Each emit path hands its event the device that caused it: the mint's proof
// for the sign-in's events, the envelope's device for an authenticated
// request (the person signing out, the operator revoking a session, the
// person changing their authenticator).
func TestEventsCarryTheDevice(t *testing.T) {
	// A password sign-in → TokenIssued.
	noSecondFactor(t)
	_, h := newSignInStore(t, "u1")
	c := capture(h)
	if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatal(err)
	}
	c.assertThumbs(t, "IssueToken", testJKT)

	// Logout → TokenRevoked; the admin's revoke → UserTokenRevoked (the
	// operator's device, not the revoked token's).
	s := aliceStore()
	h = &AuthServiceHandler{Query: s, Mutation: s}
	c = capture(h)
	if _, err := h.Logout(deviceCallerCtx("u1", "t-session", testJKT), &pb.LogoutReq{}); err != nil {
		t.Fatal(err)
	}
	c.assertThumbs(t, "RevokeSessionToken", testJKT)
	if _, err := h.RevokeSessions(deviceCallerCtx("admin", "t-admin", otherJKT), &pb.RevokeSessionsReq{Ids: []string{"t-other"}}); err != nil {
		t.Fatal(err)
	}
	c.assertThumbs(t, "RevokeUserToken", otherJKT)

	// The authenticator's lifecycle, from the device of the signed-in
	// person → TotpEnrolled, TotpConfirmed, TotpDisabled.
	m := &mfaMock{userEmail: "a@b.c"}
	h = newMfaHandler(m)
	c = capture(h)
	ctx := deviceCallerCtx("u1", "session-u1", otherJKT)
	secret, rc := enrolled(t, h, ctx)
	c.assertThumbs(t, "CreateTotpSecret", otherJKT)
	c.assertThumbs(t, "ConfirmTotpSecret", otherJKT)

	// A sign-in's second factor, completed with a recovery code →
	// MfaChallengeRequested, RecoveryCodeUsed, MfaVerified, TokenIssued: all
	// the device that signed the sign-in.
	c.thumbs = map[string][]string{}
	if _, challenged, err := mfaSignInGate(mintCtx(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil || !challenged {
		t.Fatalf("challenge: %v", err)
	}
	if _, err := h.VerifyMfa(mintCtx(), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: rc[0]}); err != nil {
		t.Fatalf("VerifyMfa: %v", err)
	}
	for _, rpc := range []string{"CreateMfaChallenge", "ConsumeRecoveryCode", "ConsumeMfaChallenge", "IssueToken"} {
		c.assertThumbs(t, rpc, testJKT)
	}

	c.thumbs = map[string][]string{}
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: nextCode(t, secret)}); err != nil {
		t.Fatalf("DisableTotp: %v", err)
	}
	c.assertThumbs(t, "RevokeTotpSecret", otherJKT)
}

// requestThumbprint prefers the envelope's device (the binding Authenticate
// verified) and falls back to a mint request's proof; nothing else names a
// device.
func TestRequestThumbprint(t *testing.T) {
	for name, c := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"envelope":            {deviceCallerCtx("u1", "s1", otherJKT), otherJKT},
		"mint proof":          {mintCtx(), testJKT},
		"malformed proof":     {withJKT(context.Background(), "not-a-thumbprint"), ""},
		"envelope, no device": {ctxWithCaller("u1"), ""},
		"nothing":             {context.Background(), ""},
	} {
		if got := requestThumbprint(c.ctx); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// The static half of device/events-carry-device: every event that names a
// user names the device too, unless it is listed below with the reason; and
// every emit of an event with a device binds it to the request's thumbprint,
// a field its request declares.
func TestEveryEventWithAUserCarriesTheDevice(t *testing.T) {
	// Account and grant events: caused by an operator, a seed or project
	// code as often as by a person's request, and not part of the
	// device-identity contract (token, sign-in and MFA events). Adding a
	// device to one is a separate change.
	exempt := map[string]string{
		"UserCreated":                "account lifecycle (also admin- and fixture-created)",
		"UserDeleted":                "account lifecycle (an operator's erasure)",
		"UserUpdated":                "account lifecycle (an operator's edit)",
		"UserRoleAssigned":           "grant (also the role seed and sign-up roles)",
		"UserRoleRevoked":            "grant",
		"PasswordResetRequested":     "mail delivery hint for an unauthenticated request",
		"EmailVerificationRequested": "mail delivery hint",
		"OrgMembershipAdded":         "membership grant",
		"OrgInviteAccepted":          "membership grant",
		"OAuthGrantApproved":         "grant (redeemed by an MCP client, which signs no proofs; the approving device is on the grant)",
	}
	events := readProto(t, "../../proto/events/auth_events.proto")
	msgRe := regexp.MustCompile(`(?s)message (\w+) \{(.*?)\n\}`)
	withDevice := map[string]bool{}
	checked := 0
	for _, m := range msgRe.FindAllStringSubmatch(events, -1) {
		name, body := m[1], m[2]
		if !strings.Contains(body, "(w17.event)") {
			continue
		}
		checked++
		hasUser := regexp.MustCompile(`\bstring\s+user_id\s*=`).MatchString(body)
		hasDevice := regexp.MustCompile(`\bstring\s+device_id\s*=`).MatchString(body)
		if hasDevice {
			withDevice[name] = true
		}
		if _, ok := exempt[name]; ok {
			if hasDevice {
				t.Errorf("%s carries device_id but is still listed as exempt", name)
			}
			continue
		}
		if hasUser && !hasDevice {
			t.Errorf("event %s names a user and no device_id", name)
		}
	}
	for _, ev := range []string{"TokenIssued", "TokenRevoked", "UserTokenRevoked", "MfaChallengeRequested", "MfaVerified", "RecoveryCodeUsed", "TotpEnrolled", "TotpConfirmed", "TotpDisabled", "ApiTokenCreated", "MarketingConsentChanged", "BotAllowlistChanged", "StepUpCodeRequested"} {
		if !withDevice[ev] {
			t.Errorf("%s carries no device_id", ev)
		}
	}
	if checked < 20 {
		t.Fatalf("checked %d events — the guard is not reading the catalogue", checked)
	}

	mut := readProto(t, "../../proto/mutations/auth_mutation.proto")
	emits := 0
	for rpc, body := range rpcBodies(mut) {
		em := regexp.MustCompile(`event: "(\w+)"`).FindStringSubmatch(body)
		if em == nil || !withDevice[em[1]] {
			continue
		}
		emits++
		if !regexp.MustCompile(`\{ key: "device_id",\s+value: "\$request\.thumbprint" \}`).MatchString(body) {
			t.Errorf("%s emits %s without binding device_id to $request.thumbprint", rpc, em[1])
		}
		req := regexp.MustCompile(`rpc ` + rpc + `\((\w+)\)`).FindStringSubmatch(body)
		reqBody := regexp.MustCompile(`(?s)message ` + req[1] + ` \{(.*?)\n\}`).FindStringSubmatch(mut)
		if reqBody == nil || !regexp.MustCompile(`\bstring\s+thumbprint\s*=`).MatchString(reqBody[1]) {
			t.Errorf("%s's request %s declares no thumbprint", rpc, req[1])
		}
	}
	if emits != 19 {
		t.Errorf("%d emits of a device-carrying event, want 19 (one per event, two for MarketingConsentChanged)", emits)
	}
}

// ── review round 1 ────────────────────────────────────────────

// A stalled history store holds a refusal no longer than
// signInHistoryTimeout: the write runs on a context cut off from the
// caller's cancellation but not unbounded. Both halves of the
// anti-enumeration pair wait the same bound.
func TestSignInHistory_AStalledStoreDoesNotHoldTheRefusal(t *testing.T) {
	saved := signInHistoryTimeout
	signInHistoryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { signInHistoryTimeout = saved })
	savedDummy := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = savedDummy })
	noSecondFactor(t)
	for _, email := range []string{"u1@example.com", "nobody@example.com"} {
		_, h := newSignInStore(t, "u1")
		keepHistory(h).block = true
		start := time.Now()
		_, err := h.SignIn(historyCtx(testJKT), &pb.SignInReq{Email: email, Password: "wrong"})
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s: the refusal took %v behind a stalled history store, want about %v", email, took, signInHistoryTimeout)
		}
		if status.Code(err) != codes.Unauthenticated || detailOf(t, err).GetCode() != CodeInvalidCredentials {
			t.Errorf("%s: %v, want the invalid-credentials refusal", email, err)
		}
	}
}

// erasedCli is the CLI store with user-1 erased after its code was issued:
// disabled, its address the placeholder. It counts the account reads.
type erasedCli struct {
	*cliMock
	reads *int
}

func (e erasedCli) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	*e.reads++
	return &pb.GetUserByIdResp{User: &pb.User{
		Id: in.GetUserId(), Email: erasedAddress(in.GetUserId()),
		DisabledAt: timestamppb.Now(), ErasedAt: timestamppb.Now(),
	}}, nil
}

// An attempt at an account erased before it — a code issued before the
// erasure, the placeholder typed at SignIn — is recorded as the erasure left
// the account's other rows: the placeholder address, no client address, no
// user agent.
func TestSignInHistory_AnAttemptAtAnErasedAccountIsPseudonymised(t *testing.T) {
	m := newCliMock()
	verifier := validVerifier()
	authz, err := newCliHandler(m).CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(verifier), RedirectUri: "http://127.0.0.1:54123/cb"})
	if err != nil {
		t.Fatal(err)
	}
	var reads int
	h := &AuthServiceHandler{Query: erasedCli{m, &reads}, Mutation: m, PasswordHash: testPasswordSettings()}
	log := keepHistory(h)
	if _, err := h.CliToken(historyCtx(testJKT), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier}); err == nil {
		t.Fatal("an erased account got a CLI session")
	}
	if len(log.rows) != 1 {
		t.Fatalf("%d rows, want one", len(log.rows))
	}
	r := log.rows[0]
	if r.GetUserId() != "user-1" || r.GetAddress() != "erased-user-1@erased.invalid" || r.GetIp() != "" || r.GetUserAgent() != "" ||
		r.GetOutcome() != pb.SignInOutcome_SIGN_IN_OUTCOME_ACCOUNT_DISABLED {
		t.Errorf("row = %+v, want user-1's placeholder, no client address or agent, ACCOUNT_DISABLED", r)
	}
	if reads != 1 {
		t.Errorf("the account was read %d times, want once: the history reuses the account gate's read", reads)
	}

	// SignIn by the placeholder: the account read is SignIn's own.
	s := aliceStore()
	s.addUser("admin", "ops@example.com")
	he := eraseHandler(s)
	if _, err := he.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatal(err)
	}
	s.signIns = nil
	savedDummy := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = savedDummy })
	if _, err := he.SignIn(historyCtx(testJKT), &pb.SignInReq{Email: "erased-u1@erased.invalid", Password: "x"}); err == nil {
		t.Fatal("the placeholder signed in")
	}
	if len(s.signIns) != 1 || s.signIns[0].GetUserId() != "u1" || s.signIns[0].GetIp() != "" || s.signIns[0].GetUserAgent() != "" {
		t.Errorf("rows = %v, want one for u1 without the client address or agent", s.signIns)
	}
}

// mfaOutage fails the challenge read or the attempt claim with an outage.
type mfaOutage struct {
	*mfaMock
	readErr, claimErr error
}

func (m mfaOutage) GetMfaChallenge(ctx context.Context, in *pb.GetMfaChallengeReq, o ...grpc.CallOption) (*pb.GetMfaChallengeResp, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.mfaMock.GetMfaChallenge(ctx, in, o...)
}

func (m mfaOutage) RecordMfaAttempt(ctx context.Context, in *pb.RecordMfaAttemptReq, o ...grpc.CallOption) (*pb.RecordMfaAttemptResp, error) {
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	return m.mfaMock.RecordMfaAttempt(ctx, in, o...)
}

// VerifyMfa records an outage of the challenge read or of the attempt claim
// as ERROR, and a missing challenge as WRONG_CODE. The caller hears one opaque
// refusal for both refusals, and Unavailable for both outages — the code may
// have been right, so the person retries rather than retypes.
func TestSignInHistory_VerifyMfaTellsAnOutageFromAWrongCode(t *testing.T) {
	answers := map[codes.Code][]error{}
	for _, c := range []struct {
		name            string
		readErr, claimE error
		want            pb.SignInOutcome
		answer          codes.Code
	}{
		{"read outage", status.Error(codes.Unavailable, "down"), nil, pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR, codes.Unavailable},
		{"no challenge", status.Error(codes.NotFound, "no rows"), nil, pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, codes.Unauthenticated},
		{"claim outage", nil, status.Error(codes.Unavailable, "down"), pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR, codes.Unavailable},
		{"claim matched nothing", nil, status.Error(codes.NotFound, "no rows"), pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE, codes.Unauthenticated},
	} {
		m := &mfaMock{chUserID: "u1", chThumb: testJKT, chCreatedAt: timestamppb.Now()}
		o := mfaOutage{mfaMock: m, readErr: c.readErr, claimErr: c.claimE}
		h := newMfaHandler(m)
		h.Query, h.Mutation = o, o
		log := keepHistory(h)
		_, err := h.VerifyMfa(historyCtx(testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"})
		if status.Code(err) != c.answer {
			t.Errorf("%s: answered %v, want %v", c.name, err, c.answer)
		}
		answers[c.answer] = append(answers[c.answer], err)
		if len(log.rows) != 1 || log.rows[0].GetOutcome() != c.want {
			t.Errorf("%s: rows %v, want one %v", c.name, log.rows, c.want)
		}
	}
	for code, as := range answers {
		for _, a := range as[1:] {
			sameAnswer(t, code.String()+" answers", a, as[0])
		}
	}
}

// A CLI exchange whose mint fails reports it like every other refusal of
// the path: no storage text reaches the CLI.
func TestCliToken_AFailedMintLeaksNoStorageText(t *testing.T) {
	m := newCliMock()
	h := newCliHandler(m)
	verifier := validVerifier()
	authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(verifier), RedirectUri: "http://127.0.0.1:54123/cb"})
	if err != nil {
		t.Fatal(err)
	}
	m.issueErr = status.Error(codes.InvalidArgument, `pq: duplicate key value violates unique constraint "w17auth_usertoken_token_hash_key"`)
	_, err = h.CliToken(mintCtx(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
	if err == nil || strings.Contains(status.Convert(err).Message(), "pq:") || status.Code(err) != codes.Unauthenticated {
		t.Fatalf("failed mint answered %v, want the opaque refusal", err)
	}
}

// Headers and an address may carry any bytes; the row (and the Device
// label) holds valid UTF-8.
func TestSignInHistory_InvalidUTF8IsNotStored(t *testing.T) {
	noSecondFactor(t)
	savedDummy := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = savedDummy })
	m, h := newSignInStore(t, "u1")
	log := keepHistory(h)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		dpopJKTKey, testJKT,
		forwardedUserAgentMetadataKey, "Firefox\xff/130",
		clientIPMetadataKey, "203.0.113.9\xfe"))
	if _, err := h.SignIn(ctx, &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatal(err)
	}
	_, _ = h.SignIn(ctx, &pb.SignInReq{Email: "n\xffbody@example.com", Password: "x"})
	if len(log.rows) != 2 {
		t.Fatalf("%d rows, want 2", len(log.rows))
	}
	for _, r := range log.rows {
		for _, v := range []string{r.GetAddress(), r.GetIp(), r.GetUserAgent()} {
			if !utf8.ValidString(v) {
				t.Errorf("row stores invalid UTF-8 %q", v)
			}
		}
	}
	if r := log.rows[0]; r.GetUserAgent() != "Firefox\uFFFD/130" || r.GetIp() != "203.0.113.9\uFFFD" {
		t.Errorf("row client = %q / %q, want each bad byte shown as U+FFFD, not dropped", r.GetUserAgent(), r.GetIp())
	}
	// A bad byte never vanishes from an address: dropped, it would turn
	// what was typed into somebody's real address on the admin list.
	if got := log.rows[1].GetAddress(); got != "n\uFFFDbody@example.com" {
		t.Errorf("address = %q, want the bad byte as U+FFFD", got)
	}
	if len(m.registered) != 1 || !utf8.ValidString(m.registered[0].GetLabel()) || !utf8.ValidString(m.registered[0].GetIp()) {
		t.Errorf("RegisterDevice = %+v, want valid UTF-8", m.registered)
	}
}

// mfaSlowAccount is the VerifyMfa store whose account read stalls until its
// context ends, or fails at once.
type mfaSlowAccount struct {
	*mfaMock
	fail bool
}

func (m mfaSlowAccount) GetUserById(ctx context.Context, _ *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	if m.fail {
		return nil, status.Error(codes.Unavailable, "down")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(3 * time.Second):
		return nil, errors.New("the read was never cut short")
	}
}

// The erased-account read has a budget of its own: a stalled read does not
// starve the write, and the row is still written. A read that fails (or
// stalls) cannot tell whether the account was erased, so the row keeps no
// client address and no user agent.
func TestSignInHistory_TheAccountReadNeitherStarvesTheWriteNorLeaks(t *testing.T) {
	saved := signInHistoryTimeout
	signInHistoryTimeout = 200 * time.Millisecond
	t.Cleanup(func() { signInHistoryTimeout = saved })
	for _, fail := range []bool{false, true} {
		m := &mfaMock{chUserID: "u1", chThumb: testJKT, chCreatedAt: timestamppb.Now(), chConsumed: true}
		h := newMfaHandler(m)
		h.Query = mfaSlowAccount{mfaMock: m, fail: fail}
		log := keepHistory(h)
		start := time.Now()
		if _, err := h.VerifyMfa(historyCtx(testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
			t.Fatal("a consumed challenge passed")
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("fail=%v: the refusal took %v", fail, took)
		}
		if len(log.rows) != 1 {
			t.Fatalf("fail=%v: %d rows, want the row written after the read gave up", fail, len(log.rows))
		}
		if r := log.rows[0]; r.GetUserId() != "u1" || r.GetIp() != "" || r.GetUserAgent() != "" {
			t.Errorf("fail=%v: row = %+v, want u1's row without the client address or agent", fail, r)
		}
	}
}
