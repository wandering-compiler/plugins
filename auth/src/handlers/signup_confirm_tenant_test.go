package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- sign_up_confirmation × tenant_scope ------------------------------------

// tenantConfirmStore is confirmStore with the tenant half: the pending row
// keeps the tenant SignUp stamped, the claim returns it, and the two tenant
// lookups are counted so a test can tell WHEN the tenant was resolved.
type tenantConfirmStore struct {
	*confirmStore
	tenantOf  map[string]string // pending id -> tenant_id stamped at SignUp
	bySlug    map[string]string // slug -> tenant_id
	byDomain  map[string]string // host -> tenant_id
	lookups   int               // GetTenantBySlug + GetTenantByDomain calls
	createdIn []string          // tenant_id of every CreateUser
}

func (s *tenantConfirmStore) GetTenantBySlug(_ context.Context, in *pb.GetTenantBySlugReq, _ ...grpc.CallOption) (*pb.GetTenantBySlugResp, error) {
	s.lookups++
	if id, ok := s.bySlug[in.GetSlug()]; ok {
		return &pb.GetTenantBySlugResp{TenantId: id}, nil
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (s *tenantConfirmStore) GetTenantByDomain(_ context.Context, in *pb.GetTenantByDomainReq, _ ...grpc.CallOption) (*pb.GetTenantByDomainResp, error) {
	s.lookups++
	if id, ok := s.byDomain[in.GetDomain()]; ok {
		return &pb.GetTenantByDomainResp{TenantId: id}, nil
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (s *tenantConfirmStore) CreatePendingSignUp(ctx context.Context, in *pb.CreatePendingSignUpReq, opts ...grpc.CallOption) (*pb.CreatePendingSignUpResp, error) {
	resp, err := s.confirmStore.CreatePendingSignUp(ctx, in, opts...)
	if err == nil {
		s.tenantOf[resp.GetPending().GetId()] = in.GetTenantId()
	}
	return resp, err
}

func (s *tenantConfirmStore) ClaimPendingSignUp(ctx context.Context, in *pb.ClaimPendingSignUpReq, opts ...grpc.CallOption) (*pb.ClaimPendingSignUpResp, error) {
	resp, err := s.confirmStore.ClaimPendingSignUp(ctx, in, opts...)
	if err == nil {
		resp.TenantId = s.tenantOf[in.GetPendingId()]
	}
	return resp, err
}

func (s *tenantConfirmStore) CreateUser(ctx context.Context, in *pb.CreateUserReq, opts ...grpc.CallOption) (*pb.CreateUserResp, error) {
	s.createdIn = append(s.createdIn, in.GetTenantId())
	return s.confirmStore.CreateUser(ctx, in, opts...)
}

// The tenant is decided by the request that asked for the code, and carried on
// the pending row. A confirmation arriving on another tenant's host — the
// mailed link opened on the wrong address, or a crafted request — must not move
// the account there, and must not even look the tenant up again.
func TestConfirmSignUp_CreatesTheAccountInTheTenantSignUpResolved(t *testing.T) {
	s := &tenantConfirmStore{
		confirmStore: newConfirmStore(),
		tenantOf:     map[string]string{},
		bySlug:       map[string]string{"acme": "tenant-acme"},
		byDomain:     map[string]string{"globex.example": "tenant-globex"},
	}
	pinConfirmationActivation(t, s.confirmStore)
	// The tenant half, which pinConfirmationActivation replaced with the
	// tenant-less one.
	pendingSignUpTenant, confirmCreateUser = stampPendingSignUpTenant, createConfirmedUserInTenant
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	pending, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-owner", TenantSlug: "acme"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if got := s.tenantOf[pending.GetPendingId()]; got != "tenant-acme" {
		t.Fatalf("the pending row carries tenant %q, want the one SignUp resolved (tenant-acme)", got)
	}
	resolvedAtSignUp := s.lookups

	wrongHost := metadata.NewIncomingContext(context.Background(), metadata.Pairs(forwardedHostMetadataKey, "globex.example"))
	if _, err := h.ConfirmSignUp(withJKT(wrongHost, testJKT), &pb.ConfirmSignUpReq{PendingId: pending.GetPendingId(), Code: s.codes[pending.GetPendingId()]}); err != nil {
		t.Fatalf("ConfirmSignUp: %v", err)
	}
	if len(s.createdIn) != 1 || s.createdIn[0] != "tenant-acme" {
		t.Errorf("the account was created in %v, want [tenant-acme] — the tenant of the request that registered", s.createdIn)
	}
	if s.lookups != resolvedAtSignUp {
		t.Errorf("ConfirmSignUp resolved a tenant again (%d lookups after SignUp's %d)", s.lookups, resolvedAtSignUp)
	}
}

// --- sign_up_confirmation × org_invite --------------------------------------

// The invitation gate runs when the registration is REQUESTED and again when it
// is CONFIRMED: an invitation revoked or lapsed while the code is in the
// mailbox stops the confirmation, and no account is created. The open-link
// claim runs once, at SignUp — the pending registration holds the link.
func TestSignUpConfirmation_TheInviteGateRunsAgainAtConfirmation(t *testing.T) {
	h, s := confirmHandler(t)

	gateCalls, claimCalls, revoked := 0, 0, false
	prevGate, prevClaim := signupInviteGate, signupClaimInvite
	t.Cleanup(func() { signupInviteGate, signupClaimInvite = prevGate, prevClaim })
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error {
		gateCalls++
		if revoked {
			return errSignUpNotInvited
		}
		return nil
	}
	signupClaimInvite = func(context.Context, *AuthServiceHandler, string, string) error {
		claimCalls++
		return nil
	}

	pending, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-owner", InviteToken: "open-link"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if gateCalls != 1 || claimCalls != 1 {
		t.Fatalf("SignUp ran the gate %d and the claim %d times, want once each", gateCalls, claimCalls)
	}
	if len(s.users) != 0 {
		t.Fatal("SignUp created the account; the link was spent by the PENDING registration")
	}

	revoked = true // the invitation is withdrawn while the code is in the mailbox
	done, err := h.ConfirmSignUp(mintCtx(), &pb.ConfirmSignUpReq{PendingId: pending.GetPendingId(), Code: s.codes[pending.GetPendingId()]})
	if !errors.Is(err, errSignUpNotInvited) || done.GetUserId() != "" {
		t.Fatalf("ConfirmSignUp after the invitation was withdrawn: %v, %v — want the invitation refusal", done, err)
	}
	if len(s.users) != 0 {
		t.Fatalf("an account was created for a withdrawn invitation: %v", s.users)
	}
	if gateCalls != 2 || claimCalls != 1 {
		t.Errorf("gate ran %d times (want 2: SignUp and ConfirmSignUp), claim %d (want 1)", gateCalls, claimCalls)
	}

	// An invitation still standing at confirmation lets the registration in.
	revoked = false
	again, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "cto@example.com", Password: "pw-owner", InviteToken: "open-link"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if done, err := h.ConfirmSignUp(mintCtx(), &pb.ConfirmSignUpReq{PendingId: again.GetPendingId(), Code: s.codes[again.GetPendingId()]}); err != nil || done.GetUserId() == "" {
		t.Fatalf("ConfirmSignUp with the invitation standing: %v, %v", done, err)
	}
}
