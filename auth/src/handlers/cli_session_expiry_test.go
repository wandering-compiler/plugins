package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// A CLI login mints a session. Were that session given a fresh full lifetime,
// any session could renew itself indefinitely: approve a CLI login shortly
// before it expires, receive a new full-lifetime session, repeat. The session
// CliToken mints therefore inherits the approving session's expiry, capped by
// the normal TTL, with no floor — a floor would be the renewal again.

const cliExpiryTTL = 3600 // seconds; the normal session TTL in these tests

func newCliExpiryHandler(m *cliMock) *AuthServiceHandler {
	h := newCliHandler(m)
	h.SessionTokenTTLSeconds = cliExpiryTTL
	return h
}

// cliLogin runs CliAuthorize as (uid, sessionTokenID) and redeems the code.
func cliLogin(t *testing.T, h *AuthServiceHandler, uid, sessionTokenID string) (*pb.CliTokenResp, error) {
	t.Helper()
	verifier := validVerifier()
	authz, err := h.CliAuthorize(sessionCallerCtx(uid, sessionTokenID), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(verifier),
		RedirectUri:   "http://127.0.0.1:54123/cb",
	})
	if err != nil {
		t.Fatalf("CliAuthorize: %v", err)
	}
	return h.CliToken(mintCtx(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
}

func TestCliToken_InheritsTheApprovingSessionsEarlierExpiry(t *testing.T) {
	m := newCliMock()
	approving := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	m.session("sess-1", "u1", &approving)
	h := newCliExpiryHandler(m)

	if _, err := cliLogin(t, h, "u1", "sess-1"); err != nil {
		t.Fatalf("CliToken: %v", err)
	}
	if m.issuedExpiry == nil || !m.issuedExpiry.AsTime().Equal(approving) {
		t.Fatalf("CLI session expires at %v, want the approving session's %v — a fresh lifetime lets a session renew itself",
			m.issuedExpiry.AsTime(), approving)
	}
}

// The cap works the other way too: a long-lived approving session does not
// lend the CLI session more than the normal TTL.
func TestCliToken_NeverOutlivesTheNormalTTL(t *testing.T) {
	m := newCliMock()
	approving := time.Now().Add(10 * 24 * time.Hour)
	m.session("sess-1", "u1", &approving)
	h := newCliExpiryHandler(m)

	before := time.Now()
	if _, err := cliLogin(t, h, "u1", "sess-1"); err != nil {
		t.Fatalf("CliToken: %v", err)
	}
	got := m.issuedExpiry.AsTime()
	if got.Before(before.Add(cliExpiryTTL*time.Second)) || got.After(time.Now().Add(cliExpiryTTL*time.Second)) {
		t.Errorf("CLI session expires at %v, want the normal TTL from now (%ds)", got, cliExpiryTTL)
	}
}

// An approving session that never expires (expires_at NULL) gives the normal
// TTL — not a never-expiring CLI session.
func TestCliToken_ANonExpiringApproverGivesTheNormalTTL(t *testing.T) {
	m := newCliMock()
	m.session("sess-1", "u1", nil)
	h := newCliExpiryHandler(m)

	before := time.Now()
	if _, err := cliLogin(t, h, "u1", "sess-1"); err != nil {
		t.Fatalf("CliToken: %v", err)
	}
	if m.issuedExpiry == nil {
		t.Fatal("CLI session minted with no expiry")
	}
	got := m.issuedExpiry.AsTime()
	if got.Before(before.Add(cliExpiryTTL*time.Second)) || got.After(time.Now().Add(cliExpiryTTL*time.Second)) {
		t.Errorf("CLI session expires at %v, want the normal TTL from now (%ds)", got, cliExpiryTTL)
	}
}

// The renewal loop itself: the CLI session approves the next CLI login, and so
// on. Every link ends when the first session does.
func TestCliToken_AChainOfLoginsCannotExtendTheFirstSession(t *testing.T) {
	m := newCliMock()
	first := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	m.session("sess-1", "u1", &first)
	h := newCliExpiryHandler(m)

	approver := "sess-1"
	for i := 0; i < 3; i++ {
		if _, err := cliLogin(t, h, "u1", approver); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if !m.issuedExpiry.AsTime().Equal(first) {
			t.Fatalf("login %d: CLI session expires at %v, after the first session's %v", i, m.issuedExpiry.AsTime(), first)
		}
		// The minted session (the mock always names it tok-1) approves next.
		exp := m.issuedExpiry.AsTime()
		m.session("tok-1", "u1", &exp)
		approver = "tok-1"
	}
}

// A session that is gone, expired, or someone else's backs no approval. Read
// as "no cap" instead, a revoked session would get a fresh full-lifetime one.
func TestCliAuthorize_RefusesAnApproverThatIsNotALiveSessionOfTheCaller(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name  string
		setup func(*cliMock)
	}{
		{"revoked", func(m *cliMock) { m.session("other", "u1", nil) }},
		{"expired", func(m *cliMock) { m.session("sess-1", "u1", &past) }},
		{"another user's token id", func(m *cliMock) { m.session("sess-1", "u2", nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newCliMock()
			tc.setup(m)
			h := newCliExpiryHandler(m)
			_, err := h.CliAuthorize(sessionCallerCtx("u1", "sess-1"), &pb.CliAuthorizeReq{
				CodeChallenge: pkceChallenge(validVerifier()),
				RedirectUri:   "http://127.0.0.1:1/cb",
			})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("err = %v, want Unauthenticated", err)
			}
			if len(m.codes) != 0 {
				t.Errorf("a refused approval still stored a code: %d stored", len(m.codes))
			}
		})
	}
}

// A read that does not answer must not become "no cap": it refuses, as an
// outage rather than as a bad credential.
func TestCliAuthorize_RefusesWhenTheSessionReadFails(t *testing.T) {
	m := newCliMock()
	m.sessionErr = status.Error(codes.Unavailable, "db down")
	h := newCliExpiryHandler(m)
	_, err := h.CliAuthorize(sessionCallerCtx("u1", "sess-1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(validVerifier()),
		RedirectUri:   "http://127.0.0.1:1/cb",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
	if len(m.codes) != 0 {
		t.Errorf("a failed read still stored a code: %d stored", len(m.codes))
	}
}

// emptySessionMock answers the session read with an empty row — what a query
// edited to drop its projection would return. "No row" must not read as
// "found, never expires".
type emptySessionMock struct{ *cliMock }

func (emptySessionMock) GetLiveSessionExpiry(context.Context, *pb.GetLiveSessionExpiryReq, ...grpc.CallOption) (*pb.GetLiveSessionExpiryResp, error) {
	return &pb.GetLiveSessionExpiryResp{}, nil
}

func TestCliAuthorize_AnEmptySessionAnswerIsNotANonExpiringSession(t *testing.T) {
	m := emptySessionMock{cliMock: newCliMock()}
	h := &AuthServiceHandler{Query: m, Mutation: m.cliMock, SessionTokenTTLSeconds: cliExpiryTTL}
	_, err := h.CliAuthorize(sessionCallerCtx("u1", "sess-1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(validVerifier()),
		RedirectUri:   "http://127.0.0.1:1/cb",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if len(m.codes) != 0 {
		t.Errorf("an empty answer still stored a code: %d stored", len(m.codes))
	}
}

// The approving session expires between authorize and exchange. A session
// minted then would be dead on arrival, so the exchange refuses — and mints
// nothing.
func TestCliToken_RefusesWhenTheApprovingSessionExpiredMeanwhile(t *testing.T) {
	m := newCliMock()
	soon := time.Now().Add(time.Minute)
	m.session("sess-1", "u1", &soon)
	h := newCliExpiryHandler(m)
	verifier := validVerifier()
	authz, err := h.CliAuthorize(sessionCallerCtx("u1", "sess-1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(verifier),
		RedirectUri:   "http://127.0.0.1:1/cb",
	})
	if err != nil {
		t.Fatalf("CliAuthorize: %v", err)
	}
	// Time passes: the bound expiry is now behind us.
	m.codes[sha256Hex(authz.GetCode())].sessionExpiresAt = timestamppb.New(time.Now().Add(-time.Second))

	_, err = h.CliToken(mintCtx(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if !errors.Is(err, errCliSessionNotLive) {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	if m.issuedHash != "" {
		t.Error("a session was minted for an approver that had already expired")
	}
}

func TestCliSessionExpiry(t *testing.T) {
	now := time.Now()
	normal := timestamppb.New(now.Add(time.Hour))
	for _, tc := range []struct {
		name      string
		approving *timestamppb.Timestamp
		want      *timestamppb.Timestamp
	}{
		{"never-expiring approver", nil, normal},
		{"earlier approver wins", timestamppb.New(now.Add(time.Minute)), timestamppb.New(now.Add(time.Minute))},
		{"later approver is capped", timestamppb.New(now.Add(48 * time.Hour)), normal},
		{"equal", timestamppb.New(now.Add(time.Hour)), normal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cliSessionExpiry(normal, tc.approving)
			if !got.AsTime().Equal(tc.want.AsTime()) {
				t.Errorf("got %v, want %v", got.AsTime(), tc.want.AsTime())
			}
		})
	}
}
