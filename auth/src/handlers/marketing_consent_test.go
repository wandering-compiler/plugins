package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

type consentMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	readFor string
	stored  *pb.GetUserMarketingConsentResp
	set     *pb.SetUserMarketingConsentReq
	at      time.Time
	err     error // GetUserMarketingConsent's
	// withdrew: what WithdrawUserMarketingConsent wrote; beforeWithdraw runs
	// first inside it — the user deciding at that instant.
	withdrew       *pb.WithdrawUserMarketingConsentReq
	beforeWithdraw func()
}

// WithdrawUserMarketingConsent applies its statement's condition to stored.
func (m *consentMock) WithdrawUserMarketingConsent(_ context.Context, in *pb.WithdrawUserMarketingConsentReq, _ ...grpc.CallOption) (*pb.SetUserMarketingConsentResp, error) {
	if f := m.beforeWithdraw; f != nil {
		m.beforeWithdraw = nil
		f()
	}
	if m.err != nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	d := m.stored.GetDecidedAt()
	if d != nil && !(m.stored.GetConsent() && d.AsTime().Before(in.GetWithdrawnAt().AsTime())) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.withdrew = in
	m.stored = &pb.GetUserMarketingConsentResp{Consent: false, DecidedAt: in.GetWithdrawnAt()}
	return &pb.SetUserMarketingConsentResp{UserId: in.GetUserId(), Consent: false, DecidedAt: in.GetWithdrawnAt()}, nil
}

func (m *consentMock) GetUserMarketingConsent(_ context.Context, in *pb.GetUserMarketingConsentReq, _ ...grpc.CallOption) (*pb.GetUserMarketingConsentResp, error) {
	m.readFor = in.GetUserId()
	if m.err != nil {
		return nil, m.err
	}
	return m.stored, nil
}

func (m *consentMock) SetUserMarketingConsent(_ context.Context, in *pb.SetUserMarketingConsentReq, _ ...grpc.CallOption) (*pb.SetUserMarketingConsentResp, error) {
	m.set = in
	return &pb.SetUserMarketingConsentResp{UserId: in.GetUserId(), Consent: in.GetConsent(), DecidedAt: timestamppb.New(m.at)}, nil
}

// marketing_consent/caller-only: both calls act on the authenticated caller,
// and the request has no field that could name anyone else.
func TestSetMarketingConsent_RecordsTheCallersDecision(t *testing.T) {
	at := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	for _, consent := range []bool{true, false} {
		m := &consentMock{at: at}
		h := &AuthServiceHandler{Query: m, Mutation: m}
		resp, err := h.SetMarketingConsent(orgAuthedCtx("u1"), &pb.SetMarketingConsentReq{Consent: consent})
		if err != nil {
			t.Fatalf("consent %v: %v", consent, err)
		}
		if m.set.GetUserId() != "u1" || m.set.GetConsent() != consent {
			t.Errorf("consent %v: wrote %+v, want the caller's own decision", consent, m.set)
		}
		if resp.GetConsent() != consent || !resp.GetDecidedAt().AsTime().Equal(at) {
			t.Errorf("consent %v: answered %+v, want what was stored", consent, resp)
		}
	}
}

func TestGetMarketingConsent_NeverAskedHasNoDecisionTime(t *testing.T) {
	m := &consentMock{stored: &pb.GetUserMarketingConsentResp{}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.GetMarketingConsent(orgAuthedCtx("u1"), &pb.GetMarketingConsentReq{})
	if err != nil {
		t.Fatal(err)
	}
	if m.readFor != "u1" {
		t.Errorf("read the consent of %q, want the caller's", m.readFor)
	}
	if resp.GetConsent() || resp.GetDecidedAt() != nil {
		t.Errorf("never asked = %+v, want no consent and no decision time", resp)
	}
}

func TestMarketingConsent_NeedsACaller(t *testing.T) {
	m := &consentMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.SetMarketingConsent(context.Background(), &pb.SetMarketingConsentReq{Consent: true}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("Set without a caller: %v, want Unauthenticated", err)
	}
	if _, err := h.GetMarketingConsent(context.Background(), &pb.GetMarketingConsentReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("Get without a caller: %v, want Unauthenticated", err)
	}
	if m.set != nil || m.readFor != "" {
		t.Error("a call without a caller reached the store")
	}
}

// marketing_consent/answered-by-authenticate: the consent the token lookup
// read reaches AuthResp, through either resolver, and so the request stream.
func TestAuthenticate_AnswersTheMarketingConsent(t *testing.T) {
	for name, res := range resolvers {
		for _, consent := range []bool{true, false} {
			req := &pb.AuthReq{Headers: map[string]string{"authorization": "DPoP tok", dpopJKTKey: testJKT}}
			resp, err := bindingAuthenticate(t, res, &bindingQuery{thumb: testJKT, known: "tok", consent: consent}, req)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if resp.GetMarketingConsent() != consent {
				t.Errorf("%s: AuthResp.marketing_consent = %v, want %v", name, resp.GetMarketingConsent(), consent)
			}
		}
	}
}

// marketing_consent/one-statement: the decision, its time and the event are
// one write — a consent recorded without its time, or announced without being
// stored, cannot happen.
func TestSetUserMarketingConsent_StampsAndAnnouncesInOneStatement(t *testing.T) {
	body := mutationRPCBody(t, "SetUserMarketingConsent")
	for _, want := range []string{
		"marketing_consent = :consent",
		"marketing_consent_at = NOW()",
		"WHERE id = :user_id",
		`event: "MarketingConsentChanged"`,
		`{ key: "consent",    value: "$response.consent" }`,
		`{ key: "decided_at", value: "$response.decided_at" },`,
		`{ key: "device_id",  value: "$request.thumbprint" }`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SetUserMarketingConsent lacks %q", want)
		}
	}
}

// Both token lookups project the consent, or one Authenticate path answers
// false for everybody.
func TestTokenLookupsProjectTheMarketingConsent(t *testing.T) {
	for _, rpc := range []string{"GetUserByTokenWithPermissions", "GetTokenWithType"} {
		if !strings.Contains(queryRPCBody(t, rpc), "?feature(marketing_consent) u.marketing_consent AS user.marketing_consent") {
			t.Errorf("%s does not project the marketing consent", rpc)
		}
	}
}

func withdraw(t *testing.T, m *consentMock, user string, at time.Time) *pb.MarketingConsentResp {
	t.Helper()
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.WithdrawMarketingConsent(context.Background(), &pb.WithdrawMarketingConsentReq{UserId: user, WithdrawnAt: timestamppb.New(at)})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// marketing_consent/withdraw-only: a withdrawal made in the marketing tool is
// written as false at the time it was made, over a yes decided before it or
// no decision; a withdrawal already on record keeps its time; a request
// naming nobody or no time, or an unknown user, is refused.
func TestWithdrawMarketingConsent_OnlyWithdraws(t *testing.T) {
	day1 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)
	for _, stored := range []*pb.GetUserMarketingConsentResp{{Consent: true, DecidedAt: timestamppb.New(day1)}, {}} {
		m := &consentMock{stored: stored}
		resp := withdraw(t, m, "u1", day2)
		if m.withdrew == nil || m.withdrew.GetUserId() != "u1" || resp.GetConsent() || !resp.GetDecidedAt().AsTime().Equal(day2) {
			t.Errorf("stored %+v: wrote %+v, answered %+v", stored, m.withdrew, resp)
		}
	}
	m := &consentMock{stored: &pb.GetUserMarketingConsentResp{Consent: false, DecidedAt: timestamppb.New(day1)}}
	if resp := withdraw(t, m, "u1", day2); m.withdrew != nil || !resp.GetDecidedAt().AsTime().Equal(day1) {
		t.Errorf("a withdrawal on record was written again (%+v) or answered %+v", m.withdrew, resp)
	}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.WithdrawMarketingConsent(context.Background(), &pb.WithdrawMarketingConsentReq{WithdrawnAt: timestamppb.New(day2)}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no user: %v, want InvalidArgument", err)
	}
	if _, err := h.WithdrawMarketingConsent(context.Background(), &pb.WithdrawMarketingConsentReq{UserId: "u1"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no withdrawn_at: %v, want InvalidArgument", err)
	}
	gone := &consentMock{err: status.Error(codes.NotFound, "no such user")}
	h = &AuthServiceHandler{Query: gone, Mutation: gone}
	if _, err := h.WithdrawMarketingConsent(context.Background(), &pb.WithdrawMarketingConsentReq{UserId: "u9", WithdrawnAt: timestamppb.New(day2)}); status.Code(err) != codes.NotFound || gone.withdrew != nil {
		t.Errorf("unknown user: %v (wrote %+v), want NotFound and nothing written", err, gone.withdrew)
	}
}

// marketing_consent/withdraw-only: a late day-2 unsubscribe after a day-3
// consent writes nothing; and a consent the user gives at the very instant
// the withdrawal is written — between any read and the write — is not
// overwritten: the withdrawal is one conditional statement.
func TestWithdrawMarketingConsent_ANewerConsentStands(t *testing.T) {
	day2 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	day3 := day2.Add(24 * time.Hour)
	m := &consentMock{stored: &pb.GetUserMarketingConsentResp{Consent: true, DecidedAt: timestamppb.New(day3)}}
	if resp := withdraw(t, m, "u1", day2); m.withdrew != nil || !resp.GetConsent() || !resp.GetDecidedAt().AsTime().Equal(day3) {
		t.Errorf("late unsubscribe: wrote %+v, answered %+v; want the day-3 consent standing", m.withdrew, resp)
	}
	m = &consentMock{stored: &pb.GetUserMarketingConsentResp{Consent: true, DecidedAt: timestamppb.New(day2.Add(-time.Hour))}}
	m.beforeWithdraw = func() {
		m.stored = &pb.GetUserMarketingConsentResp{Consent: true, DecidedAt: timestamppb.New(day3)} // the user, now
	}
	if resp := withdraw(t, m, "u1", day2); m.withdrew != nil || !resp.GetConsent() || !m.stored.GetConsent() {
		t.Errorf("a consent given meanwhile was overwritten: wrote %+v, answered %+v", m.withdrew, resp)
	}
}

// marketing_consent/withdraw-only: the statement carries the condition and
// the event, so the guard and the announcement cannot come apart.
func TestWithdrawUserMarketingConsent_IsOneConditionalStatement(t *testing.T) {
	body := mutationRPCBody(t, "WithdrawUserMarketingConsent")
	for _, want := range []string{
		"marketing_consent = FALSE",
		"marketing_consent_at = :withdrawn_at",
		"WHERE id = :user_id",
		"AND (marketing_consent_at IS NULL OR (marketing_consent = TRUE AND marketing_consent_at < :withdrawn_at))",
		`event: "MarketingConsentChanged"`,
		`{ key: "consent",    value: "$response.consent" }`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("WithdrawUserMarketingConsent lacks %q", want)
		}
	}
}
