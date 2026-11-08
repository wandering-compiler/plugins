package handlers

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// floorRows is an organizations' address-proof floors store, mixed into the
// fakes of the paths that read them.
type floorRows struct {
	floors map[string]string // org id → live floor
	set    []string
	ended  []string
}

func (*floorRows) keepsEmailProofPolicies() {}

func (f *floorRows) ListOrgEmailProofPolicyRows(_ context.Context, in *pb.ListOrgEmailProofPolicyRowsReq, _ ...grpc.CallOption) (*pb.ListOrgEmailProofPolicyRowsResp, error) {
	if fl := f.floors[in.GetOrgId()]; fl != "" {
		return &pb.ListOrgEmailProofPolicyRowsResp{Policies: []*pb.OrgEmailProofPolicyRow{{Floor: fl}}}, nil
	}
	return &pb.ListOrgEmailProofPolicyRowsResp{}, nil
}

func (f *floorRows) SetOrgEmailProofPolicyRow(_ context.Context, in *pb.SetOrgEmailProofPolicyRowReq, _ ...grpc.CallOption) (*pb.SetOrgEmailProofPolicyRowResp, error) {
	f.set = append(f.set, fmt.Sprintf("%s/%s/%s", in.GetOrgId(), in.GetFloor(), in.GetSetBy()))
	return &pb.SetOrgEmailProofPolicyRowResp{}, nil
}

func (f *floorRows) EndOrgEmailProofPolicyRow(_ context.Context, in *pb.EndOrgEmailProofPolicyRowReq, _ ...grpc.CallOption) (*pb.EndOrgEmailProofPolicyRowResp, error) {
	f.ended = append(f.ended, in.GetOrgId())
	return nil, status.Error(codes.NotFound, "no rows")
}

// inviteFloorMock is the invitation gate's store with floors per organization.
type inviteFloorMock struct {
	*verifiedMock
	*floorRows
}

// An invitation into an organization is held to that organization's floor,
// and the activation's decides only where the organization has none.
func TestEmailProofFloor_TheOrganizationsOwnOverTheDefault(t *testing.T) {
	m := &inviteFloorMock{verifiedMock: &verifiedMock{}, floorRows: &floorRows{floors: map[string]string{"org-strict": emailProofFull, "org-open": emailProofNone}}}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofNone}
	ctx := context.Background()

	if err := inviteVerifiedEmailGateImpl(ctx, h, "u1", "org-strict", true); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an unproven account into an organization with full, under a none default: %v", err)
	}
	if err := inviteVerifiedEmailGateImpl(ctx, h, "u1", "org-plain", true); err != nil {
		t.Errorf("an organization with no floor, under a none default: %v", err)
	}
	h.EmailProofRequired = emailProofFull
	if err := inviteVerifiedEmailGateImpl(ctx, h, "u1", "org-open", false); err != nil {
		t.Errorf("an organization that set none, under a full default: %v", err)
	}
	if err := inviteVerifiedEmailGateImpl(ctx, h, "u1", "org-plain", false); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an organization with no floor, under a full default: %v", err)
	}
	m.verified = true
	if err := inviteVerifiedEmailGateImpl(ctx, h, "u1", "org-strict", false); err != nil {
		t.Errorf("a self-confirmed account into the strict organization: %v", err)
	}
}

// An invitation taken at registration reads the same floor: below it, the
// registration goes through and the invitation stays for later.
func TestEmailProofFloor_AnInvitationAtRegistration(t *testing.T) {
	for _, tc := range []struct {
		floor string
		bound bool
		want  bool
	}{
		{"", false, true},
		{emailProofNone, false, true},
		{emailProofDerived, true, true},
		{emailProofDerived, false, false},
		{emailProofFull, true, false},
	} {
		if got := reachesFloorAtSignup(tc.floor, tc.bound); got != tc.want {
			t.Errorf("floor %q, bound %v: %v, want %v", tc.floor, tc.bound, got, tc.want)
		}
	}
}

// hostFloorMock is the org_signup store with floors per organization.
type hostFloorMock struct {
	*hostMock
	*floorRows
}

// An open registration says anybody may join, not that the address is
// theirs. On a host whose organization asks a proof, a registration joins only
// when it proves the address itself — and is refused before anything is
// written otherwise. That holds under the activation's floor too, when the
// organization has none of its own.
func TestEmailProofFloor_ARegistrationOnTheHostNeedsItsOwnProof(t *testing.T) {
	m := &hostFloorMock{hostMock: signupFixture(), floorRows: &floorRows{floors: map[string]string{}}}
	h := &AuthServiceHandler{Query: m, InviteOnly: true, EmailProofRequired: emailProofNone}
	ctx := registrationVia("host,default", "client", "acme.example.com")

	if join, err := signupGates(ctx, h, "new@example.com", "", "", false); err != nil || join == nil {
		t.Fatalf("no floor anywhere: join %+v, err %v", join, err)
	}
	for _, floor := range []string{emailProofDerived, emailProofFull} {
		m.floors["org-acme"] = floor
		_, err := signupGates(ctx, h, "new@example.com", "", "", false)
		if refusalCodeOf(err) != CodeSignUpEmailProofRequired {
			t.Errorf("floor %s, a registration proving nothing: %v", floor, err)
		}
		if join, err := signupGates(ctx, h, "new@example.com", "", "", true); err != nil || join == nil || join.orgID != "org-acme" {
			t.Errorf("floor %s, a registration that proves the address: join %+v, err %v", floor, join, err)
		}
	}
	delete(m.floors, "org-acme")
	h.EmailProofRequired = emailProofFull
	if _, err := signupGates(ctx, h, "new@example.com", "", "", false); refusalCodeOf(err) != CodeSignUpEmailProofRequired {
		t.Errorf("the activation's full, no floor of the organization's own: %v", err)
	}
	m.floors["org-acme"] = emailProofNone
	if join, err := signupGates(ctx, h, "new@example.com", "", "", false); err != nil || join == nil {
		t.Errorf("the organization set none under a full default: join %+v, err %v", join, err)
	}
}

// floorPolicyMock is the floor methods' store: nobody holds the backoffice's
// methods realm-wide.
type floorPolicyMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	*floorRows
}

// The store's own methods, named here: the embedded clients declare them too.
func (m *floorPolicyMock) ListOrgEmailProofPolicyRows(ctx context.Context, in *pb.ListOrgEmailProofPolicyRowsReq, opts ...grpc.CallOption) (*pb.ListOrgEmailProofPolicyRowsResp, error) {
	return m.floorRows.ListOrgEmailProofPolicyRows(ctx, in, opts...)
}

func (m *floorPolicyMock) SetOrgEmailProofPolicyRow(ctx context.Context, in *pb.SetOrgEmailProofPolicyRowReq, opts ...grpc.CallOption) (*pb.SetOrgEmailProofPolicyRowResp, error) {
	return m.floorRows.SetOrgEmailProofPolicyRow(ctx, in, opts...)
}

func (m *floorPolicyMock) EndOrgEmailProofPolicyRow(ctx context.Context, in *pb.EndOrgEmailProofPolicyRowReq, opts ...grpc.CallOption) (*pb.EndOrgEmailProofPolicyRowResp, error) {
	return m.floorRows.EndOrgEmailProofPolicyRow(ctx, in, opts...)
}

func (m *floorPolicyMock) GetUserRealmWidePermissions(context.Context, *pb.GetUserRealmWidePermissionsReq, ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	return &pb.GetUserRealmWidePermissionsResp{}, nil
}

func floorPolicyFixture() (*floorPolicyMock, *AuthServiceHandler) {
	m := &floorPolicyMock{floorRows: &floorRows{floors: map[string]string{}}}
	return m, &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofDerived}
}

// The backoffice's: realm-wide, values held, each set ending the live row.
func TestSetOrgEmailProof(t *testing.T) {
	m, h := floorPolicyFixture()
	h.Lock = policyLock("SetOrgEmailProof", "ClearOrgEmailProof", "GetOrgEmailProof")
	if _, err := h.SetOrgEmailProof(whoAmICtx("admin", "org-acme"), &pb.SetOrgEmailProofReq{OrgId: "org-acme", Floor: emailProofFull}); refusalCodeOf(err) != CodeEmailProofPoliciesRealmOnly {
		t.Errorf("from inside an organization: %v", err)
	}
	realm := whoAmICtx("ops", "")
	for _, bad := range []string{"", "verified", "Full"} {
		if _, err := h.SetOrgEmailProof(realm, &pb.SetOrgEmailProofReq{OrgId: "org-acme", Floor: bad}); refusalCodeOf(err) != CodeEmailProofPolicyInvalid {
			t.Errorf("floor %q: %v", bad, err)
		}
	}
	if len(m.set) != 0 {
		t.Fatalf("a refused floor was written: %v", m.set)
	}
	if _, err := h.SetOrgEmailProof(realm, &pb.SetOrgEmailProofReq{OrgId: "org-acme", Floor: emailProofFull}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.set, []string{"org-acme/full/ops"}) || !slices.Equal(m.ended, []string{"org-acme"}) {
		t.Errorf("set %v, ended %v — a set ends the live row first", m.set, m.ended)
	}
	if _, err := h.ClearOrgEmailProof(realm, &pb.ClearOrgEmailProofReq{OrgId: "org-acme"}); err != nil {
		t.Errorf("clearing: %v", err)
	}
	m.floors["org-acme"] = emailProofFull
	resp, err := h.GetOrgEmailProof(realm, &pb.GetOrgEmailProofReq{OrgId: "org-acme"})
	if err != nil || resp.GetFloor() != emailProofFull || resp.GetDefaultFloor() != emailProofDerived {
		t.Errorf("get: %v, %v — the floor and the default beside it", resp, err)
	}
	h.EmailProofRequired = ""
	if resp, _ := h.GetOrgEmailProof(realm, &pb.GetOrgEmailProofReq{OrgId: "org-none"}); resp.GetFloor() != "" || resp.GetDefaultFloor() != emailProofNone {
		t.Errorf("an organization with none of its own, an unset default: %v", resp)
	}
}

// The organization's own, from inside it — and only with the endpoint ACL
// gating the method: otherwise every member could lower the floor.
func TestSetMyOrgEmailProof(t *testing.T) {
	m, h := floorPolicyFixture()
	inAcme := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, "admin", "x-w17-scope-org_id", "org-acme", "x-w17-scope-org_slug", "acme"))
	req := &pb.SetMyOrgEmailProofReq{Org: "acme", Floor: emailProofNone}

	if _, err := h.SetMyOrgEmailProof(inAcme, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a method the lock does not gate: %v", err)
	}
	h.Lock = policyLock("SetMyOrgEmailProof", "GetMyOrgEmailProof")
	if _, err := h.SetMyOrgEmailProof(inAcme, &pb.SetMyOrgEmailProofReq{Org: "globex", Floor: emailProofNone}); refusalCodeOf(err) != CodeOrgMismatch {
		t.Errorf("naming another organization: %v", err)
	}
	if _, err := h.SetMyOrgEmailProof(whoAmICtx("admin", ""), req); err == nil {
		t.Error("with no active organization: accepted")
	}
	if _, err := h.SetMyOrgEmailProof(inAcme, &pb.SetMyOrgEmailProofReq{Org: "acme", Floor: "maybe"}); refusalCodeOf(err) != CodeEmailProofPolicyInvalid {
		t.Errorf("an unknown floor: %v", err)
	}
	if len(m.set) != 0 {
		t.Fatalf("a refused floor was written: %v", m.set)
	}
	if _, err := h.SetMyOrgEmailProof(inAcme, req); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.set, []string{"org-acme/none/admin"}) {
		t.Errorf("set %v — the active organization's, never the request's", m.set)
	}
	if _, err := h.GetMyOrgEmailProof(inAcme, &pb.GetMyOrgEmailProofReq{}); err != nil {
		t.Errorf("get: %v", err)
	}
	if _, err := h.ClearMyOrgEmailProof(inAcme, &pb.ClearMyOrgEmailProofReq{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("clear, which the lock does not gate: %v", err)
	}
}
