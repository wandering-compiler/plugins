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
}

func (m *consentMock) GetUserMarketingConsent(_ context.Context, in *pb.GetUserMarketingConsentReq, _ ...grpc.CallOption) (*pb.GetUserMarketingConsentResp, error) {
	m.readFor = in.GetUserId()
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
