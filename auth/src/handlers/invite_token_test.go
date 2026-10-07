package handlers

import (
	"context"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
	"google.golang.org/protobuf/protoadapt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// inviteTokenMock covers the three RPCs an acceptance touches, and RECORDS what it
// was asked — the assertions below are about what reached the database, not only
// about what the caller was told.
type inviteTokenMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	// what the pending read answers
	pendingEmail string // "" = an OPEN invitation
	pendingErr   error

	// what the account already holds
	accountEmail string
	accountProof pb.EmailProof

	// the role the invitation was checked against, and what it carries now.
	// snapshot "" means the role as it is ("role-1:" for livePerms nil);
	// legacy makes the claim return no snapshot at all.
	snapshot  string
	legacy    bool
	livePerms []int32

	// recorded
	consumedHash    string
	derivedFor      string
	assignedOrg     string
	addedMembership bool
}

func (m *inviteTokenMock) GetPendingOrgInviteByToken(_ context.Context, in *pb.GetPendingOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.GetPendingOrgInviteByTokenResp, error) {
	if m.pendingErr != nil {
		return nil, m.pendingErr
	}
	return &pb.GetPendingOrgInviteByTokenResp{OrgId: "org-1", Role: "member", Email: m.pendingEmail}, nil
}

func (m *inviteTokenMock) ConsumeOrgInviteByToken(_ context.Context, in *pb.ConsumeOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	m.consumedHash = in.GetTokenHash()
	snap := m.snapshot
	if snap == "" && !m.legacy {
		snap = "role-1:"
	}
	return &pb.ConsumeOrgInviteByTokenResp{OrgId: "org-1", Role: "member", Email: m.pendingEmail, RoleSnapshot: snap}, nil
}

func (m *inviteTokenMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{
		Id: in.GetUserId(), Email: m.accountEmail, EmailProof: m.accountProof,
	}}, nil
}

func (m *inviteTokenMock) ListRoles(_ context.Context, _ *pb.ListRolesReq, _ ...grpc.CallOption) (*pb.ListRolesResp, error) {
	return &pb.ListRolesResp{Roles: []*pb.Role{{Id: "role-1", Name: "member"}}}, nil
}

func (m *inviteTokenMock) ListOrgScopedRoles(_ context.Context, _ *pb.ListOrgScopedRolesReq, _ ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: []*pb.OrgScopedRole{{Id: "role-1", Name: "member"}}}, nil
}

func (m *inviteTokenMock) ListRoleGrants(_ context.Context, _ *pb.ListRoleGrantsReq, _ ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	return &pb.ListRoleGrantsResp{Grants: []*pb.RoleGrant{{RoleId: "role-1", PermissionIds: m.livePerms}}}, nil
}

func (m *inviteTokenMock) AddOrgMembership(_ context.Context, _ *pb.AddOrgMembershipReq, _ ...grpc.CallOption) (*pb.AddOrgMembershipResp, error) {
	m.addedMembership = true
	return &pb.AddOrgMembershipResp{}, nil
}

func (m *inviteTokenMock) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.assignedOrg = in.GetOrgId()
	return &pb.AssignRoleToUserResp{}, nil
}

func (m *inviteTokenMock) MarkEmailDerivedFromInvite(_ context.Context, in *pb.MarkEmailDerivedFromInviteReq, _ ...grpc.CallOption) (*pb.MarkEmailDerivedFromInviteResp, error) {
	m.derivedFor = in.GetUserId()
	return &pb.MarkEmailDerivedFromInviteResp{UserId: in.GetUserId()}, nil
}

// withRealSeams installs the implementations the `email_verification` staging
// normally installs, so a test exercises the gate and the derivation rather than
// the no-op defaults. Without this a mode test passes for the wrong reason: the
// seam returns nil for every floor.
func withRealSeams(t *testing.T) {
	t.Helper()
	gate, derive := inviteVerifiedEmailGate, markEmailDerived
	inviteVerifiedEmailGate, markEmailDerived = inviteVerifiedEmailGateImpl, markEmailDerivedImpl
	t.Cleanup(func() { inviteVerifiedEmailGate, markEmailDerived = gate, derive })
}

// THE CORRECTION, as a test. A BOUND invitation derives the address; an OPEN one
// derives nothing, and the middle floor must tell them apart.
//
// Jiri's requirement asked for both paths to be pre-verified. Open signup cannot
// be: the registrant picks the address and the link may have travelled by a
// channel that has no address at all, so what was proved is that they were
// AUTHORISED. Marking that derived would be a claim with no evidence — and worse
// than unproven, because it reads as stronger.
func TestEmailProofGate_DerivedFloorSeparatesBoundFromOpen(t *testing.T) {
	withRealSeams(t)

	t.Run("bound invitation passes with no prior proof", func(t *testing.T) {
		m := &inviteTokenMock{accountEmail: "her@corp.example", accountProof: pb.EmailProof_UNPROVEN}
		h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofDerived}
		if err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", true); err != nil {
			t.Fatalf("a bound invitation was refused at the derived floor — the corporate case now needs a round trip nobody asked for: %v", err)
		}
	})

	t.Run("open invitation is refused", func(t *testing.T) {
		m := &inviteTokenMock{accountEmail: "anything@example.com", accountProof: pb.EmailProof_UNPROVEN}
		h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofDerived}
		err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false)
		if err == nil {
			t.Fatal("an OPEN invitation satisfied the derived floor — authorisation was counted as address proof, which is the one thing this floor exists to refuse")
		}
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("code = %s, want FailedPrecondition", status.Code(err))
		}
	})
}

// The floors are ORDERED, and the middle one is not the top one.
func TestEmailProofGate_AlreadyDerivedSatisfiesDerivedButNotFull(t *testing.T) {
	withRealSeams(t)
	m := &inviteTokenMock{accountEmail: "her@corp.example", accountProof: pb.EmailProof_DERIVED_FROM_INVITE}

	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofDerived}
	if err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false); err != nil {
		t.Errorf("an address derived on an earlier bound invitation was refused at its own floor: %v", err)
	}

	h.EmailProofRequired = emailProofFull
	if err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false); err == nil {
		t.Error("a derived address satisfied the FULL floor — then the two modes are one mode, and the boolean this replaced was enough")
	}
}

// Accepting a BOUND invitation records HOW the address was proved. Asserted on the
// call that reaches the database, not on the response: the response says nothing
// about the proof, and a handler that returned success without recording it would
// pass a response-only test.
func TestAcceptOrgInvite_BoundRecordsDerivedAndOpenDoesNot(t *testing.T) {
	withRealSeams(t)

	t.Run("bound", func(t *testing.T) {
		m := &inviteTokenMock{pendingEmail: "her@corp.example", accountEmail: "her@corp.example"}
		h := &AuthServiceHandler{Query: m, Mutation: m}
		if _, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "secret"}); err != nil {
			t.Fatalf("AcceptOrgInvite: %v", err)
		}
		if m.derivedFor != "u1" {
			t.Error("a bound invitation was accepted and the address was left UNPROVEN — the derivation is the reason the corporate path needs no verification mail")
		}
		if !m.addedMembership || m.assignedOrg != "org-1" {
			t.Error("the membership or the org-scoped grant did not land")
		}
	})

	t.Run("open", func(t *testing.T) {
		m := &inviteTokenMock{pendingEmail: "", accountEmail: "whatever@example.com"}
		h := &AuthServiceHandler{Query: m, Mutation: m}
		if _, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "secret"}); err != nil {
			t.Fatalf("AcceptOrgInvite: %v", err)
		}
		if m.derivedFor != "" {
			t.Errorf("an OPEN invitation derived a proof for %q — nothing about that address was proved, and a mark that says otherwise is worse than none", m.derivedFor)
		}
		if !m.addedMembership {
			t.Error("the membership did not land — an open invitation still admits the person, it just proves nothing about their address")
		}
	})
}

// A BOUND invitation belongs to one address. Presented by another account it gets
// the OPAQUE refusal — the same sentence a wrong or spent token gets, so a guesser
// cannot learn that the token was good and only the account was wrong.
func TestAcceptOrgInvite_BoundInvitationRefusesAnotherAddressOpaquely(t *testing.T) {
	withRealSeams(t)
	m := &inviteTokenMock{pendingEmail: "her@corp.example", accountEmail: "someone.else@example.com"}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	_, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "secret"})
	if err == nil {
		t.Fatal("an invitation bound to one address was accepted by another account")
	}
	if !strings.Contains(err.Error(), "invitation invalid") {
		t.Errorf("the refusal is not the opaque one: %v", err)
	}
	if m.consumedHash != "" {
		t.Error("the invitation was CONSUMED before being refused — the rightful invitee can no longer use it")
	}
}

// The token is hashed on the way in. Nothing the caller typed reaches the store.
func TestAcceptOrgInvite_ConsumesTheHashNotThePlaintext(t *testing.T) {
	withRealSeams(t)
	m := &inviteTokenMock{pendingEmail: "", accountEmail: "a@b.example"}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "plaintext-secret"}); err != nil {
		t.Fatalf("AcceptOrgInvite: %v", err)
	}
	if m.consumedHash == "plaintext-secret" {
		t.Fatal("the plaintext token was used as the lookup key — then the column holds a credential")
	}
	if m.consumedHash != sha256Hex("plaintext-secret") {
		t.Errorf("consumed %q, want sha256 of the token", m.consumedHash)
	}
}

// A token nothing matches is the opaque refusal, and it must not be reported as the
// NOT_FOUND of an internal RPC — the mistake this plugin already made once on the
// claim path.
func TestAcceptOrgInvite_AnUnknownTokenIsOpaque(t *testing.T) {
	withRealSeams(t)
	m := &inviteTokenMock{pendingErr: status.Error(codes.NotFound, "GetPendingOrgInviteByToken: no rows")}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	_, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "nope"})
	if err == nil {
		t.Fatal("an unknown token was accepted")
	}
	if !strings.Contains(err.Error(), "invitation invalid") {
		t.Errorf("not the opaque refusal: %v", err)
	}
	if strings.Contains(err.Error(), "GetPendingOrgInviteByToken") {
		t.Errorf("the refusal names an internal RPC: %v", err)
	}
}

// mintMock records what the CREATE was asked to store.
type mintMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	storedHash     string
	storedEmail    string
	storedMetadata string
}

func (m *mintMock) ListRoles(_ context.Context, _ *pb.ListRolesReq, _ ...grpc.CallOption) (*pb.ListRolesResp, error) {
	return &pb.ListRolesResp{Roles: []*pb.Role{{Id: "role-1", Name: "member"}}}, nil
}

func (m *mintMock) ListOrgScopedRoles(_ context.Context, _ *pb.ListOrgScopedRolesReq, _ ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: []*pb.OrgScopedRole{{Id: "role-1", Name: "member"}}}, nil
}

func (m *mintMock) ListRoleGrants(_ context.Context, _ *pb.ListRoleGrantsReq, _ ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	return &pb.ListRoleGrantsResp{Grants: []*pb.RoleGrant{{RoleId: "role-1"}}}, nil
}

func (m *mintMock) ClearExpiredOrgInvite(_ context.Context, _ *pb.ClearExpiredOrgInviteReq, _ ...grpc.CallOption) (*pb.ClearExpiredOrgInviteResp, error) {
	return &pb.ClearExpiredOrgInviteResp{}, nil
}

func (m *mintMock) CreateOrgInvite(_ context.Context, in *pb.CreateOrgInviteReq, _ ...grpc.CallOption) (*pb.CreateOrgInviteResp, error) {
	m.storedHash = in.GetTokenHash()
	m.storedEmail = in.GetEmail()
	m.storedMetadata = in.GetMetadata()
	return &pb.CreateOrgInviteResp{Invite: &pb.OrgInvite{
		Id: "inv-1", OrgId: "org-1", Email: in.GetEmail(), Role: in.GetRole(),
	}}, nil
}

// The inviter gets the link's secret ONCE, and the row keeps only its hash.
//
// Both halves, because each alone is a defect: without the plaintext the inviter
// has nothing to send and the feature does not work; with the plaintext in the row
// the column is a stored credential. This is the one place the two differ from a
// password reset, where the token goes to the mailbox and never to a caller — here
// the inviter IS the delivery channel.
func TestInviteToOrg_ReturnsThePlaintextOnceAndStoresTheHash(t *testing.T) {
	m := &mintMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	resp, err := h.InviteToOrg(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{
		Email: "Her@Corp.Example", Role: "member",
	})
	if err != nil {
		t.Fatalf("InviteToOrg: %v", err)
	}
	if resp.GetToken() == "" {
		t.Fatal("no token came back — the inviter is the delivery channel and has nothing to send")
	}
	if m.storedHash == resp.GetToken() {
		t.Fatal("the row stored the PLAINTEXT — that column is then a credential at rest")
	}
	if m.storedHash != sha256Hex(resp.GetToken()) {
		t.Errorf("stored %q, want sha256 of the returned token", m.storedHash)
	}
	// The summary must not carry it: a list of an org's outstanding invitations
	// would then show a secret long after the moment it was handed over.
	if strings.Contains(resp.GetInvite().String(), resp.GetToken()) {
		t.Error("the token appears in the invite SUMMARY, which is what a list renders")
	}
	// And the address is stored normalized, which is why an invitation matches the
	// account that arrives — SignIn lower-cases what it looks up.
	if m.storedEmail != "her@corp.example" {
		t.Errorf("stored email = %q, want it normalized", m.storedEmail)
	}
}

// What reaches the column when the caller sends no metadata — and the answer
// cannot be "whatever the caller sent", because the column is JSON NOT NULL and
// the empty string is not a JSON document.
//
// This shipped broken in rc.8 and was found against PRODUCTION, not here: an
// invitation with no metadata answered INVALID_ARGUMENT / VALUE_OUT_OF_RANGE with
// an EMPTY field, which is grpcerr's fallback for a Postgres data exception
// (wrap.go:433 — it names no column because PG reports none). So an OPTIONAL
// field had become required, refusing in the one shape a client cannot act on.
//
// The three cases are one rule stated from both ends: nothing becomes `{}`, and
// anything else is the consumer's document and is not touched.
func TestInviteToOrg_AbsentMetadataBecomesTheEmptyObject(t *testing.T) {
	for _, tc := range []struct{ name, sent, want string }{
		{"omitted", "", "{}"},
		{"whitespace only", "   \n", "{}"},
		{"a document is stored byte for byte", `{"tenant":"t1","object":"o2"}`, `{"tenant":"t1","object":"o2"}`},
		// Not this plugin's business to judge: the column is the consumer's, and
		// nothing here reads it. A value the DATABASE rejects is the database's
		// refusal to make, not a silent rewrite here.
		{"a non-object document survives", `[1,2,3]`, `[1,2,3]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &mintMock{}
			h := &AuthServiceHandler{Query: m, Mutation: m}
			if _, err := h.InviteToOrg(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{
				Email: "her@corp.example", Role: "member", Metadata: tc.sent,
			}); err != nil {
				t.Fatalf("InviteToOrg: %v", err)
			}
			if m.storedMetadata != tc.want {
				t.Errorf("stored metadata = %q, want %q", m.storedMetadata, tc.want)
			}
		})
	}
}

// An OPEN invitation stores no address. It is a real request, not a validation
// failure — path 1 of the three.
func TestInviteToOrg_AnOpenInvitationStoresNoAddress(t *testing.T) {
	m := &mintMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	resp, err := h.InviteToOrg(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{Role: "member"})
	if err != nil {
		t.Fatalf("an invitation with no address was refused, and it is one of the three paths: %v", err)
	}
	if m.storedEmail != "" {
		t.Errorf("stored email = %q, want empty — an open invitation binds nobody", m.storedEmail)
	}
	if resp.GetToken() == "" {
		t.Error("an open invitation still needs its secret — the link IS the authorisation")
	}
}

// signupTokenMock answers the two lookups the sign-up gate can make, and records
// whether the invitation was SPENT — the token must survive a signup.
type signupTokenMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	pendingEmail string // what the token resolves to; "" = an OPEN invitation
	tokenErr     error  // set to NotFound for a token that matches nothing
	byAddress    []*pb.PendingInviteRow
	consumed     bool
	binds        []*pb.BindOpenOrgInviteReq
}

// BindOpenOrgInvite behaves as its WHERE does: it binds only an open
// invitation, and the read-back then sees the bound address.
func (m *signupTokenMock) BindOpenOrgInvite(_ context.Context, in *pb.BindOpenOrgInviteReq, _ ...grpc.CallOption) (*pb.BindOpenOrgInviteResp, error) {
	m.binds = append(m.binds, in)
	if m.tokenErr == nil && m.pendingEmail == "" {
		m.pendingEmail = in.GetEmail()
	}
	return &pb.BindOpenOrgInviteResp{}, nil
}

func (m *signupTokenMock) GetPendingOrgInviteByToken(_ context.Context, _ *pb.GetPendingOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.GetPendingOrgInviteByTokenResp, error) {
	if m.tokenErr != nil {
		return nil, m.tokenErr
	}
	return &pb.GetPendingOrgInviteByTokenResp{OrgId: "org-1", Role: "member", Email: m.pendingEmail}, nil
}

func (m *signupTokenMock) ListPendingInvitesForEmail(_ context.Context, _ *pb.ListPendingInvitesForEmailReq, _ ...grpc.CallOption) (*pb.ListPendingInvitesForEmailResp, error) {
	return &pb.ListPendingInvitesForEmailResp{Invites: m.byAddress}, nil
}

func (m *signupTokenMock) ConsumeOrgInviteByToken(_ context.Context, _ *pb.ConsumeOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	m.consumed = true
	return &pb.ConsumeOrgInviteByTokenResp{}, nil
}

// PATH 1, and it did not work when the model was first written.
//
// `invite_only` asks "was THIS ADDRESS invited?" and an OPEN invitation names no
// address, so the address lookup can never find it — which refused every holder of
// an open link, in the DEFAULT configuration (`invite_only` defaults on). Found by
// review rather than by a consumer, which is the only reason it is not a report.
func TestSignupInviteGate_AnOpenLinkAdmitsAnyAddress(t *testing.T) {
	m := &signupTokenMock{pendingEmail: ""} // open invitation, nobody invited by address
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}

	if err := requirePendingInvite(context.Background(), h, "anyone@example.com", "the-link-secret"); err != nil {
		t.Fatalf("a holder of an OPEN invitation was refused registration — that is path 1, and it is the default configuration: %v", err)
	}
	// The invitation is single-use and ACCEPTANCE spends it. A signup that burnt
	// the link would leave the person registered and unable to join the org.
	if m.consumed {
		t.Error("the signup CONSUMED the invitation — the acceptance that follows now has nothing to spend")
	}
}

// A BOUND invitation's token is not a transferable pass: it still belongs to its
// own address, so presenting it from another one falls through to the address
// check and is refused.
func TestSignupInviteGate_ABoundTokenDoesNotAdmitAnotherAddress(t *testing.T) {
	m := &signupTokenMock{pendingEmail: "her@corp.example"} // bound; nobody invited by the address below
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}

	if err := requirePendingInvite(context.Background(), h, "someone.else@example.com", "her-link"); err != nil {
		return // refused, as it must be
	}
	t.Fatal("a token bound to one address admitted a different one — the link being secret does not make it transferable")
}

// And the bound holder themselves goes through on the token, without the address
// having to be listed separately.
func TestSignupInviteGate_ABoundTokenAdmitsItsOwnAddress(t *testing.T) {
	m := &signupTokenMock{pendingEmail: "her@corp.example"}
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}

	if err := requirePendingInvite(context.Background(), h, "her@corp.example", "her-link"); err != nil {
		t.Fatalf("the invited person was refused while holding their own link: %v", err)
	}
}

// A stale token does NOT short-circuit the address check. Somebody who was properly
// invited by address and happens to paste an expired link still registers.
func TestSignupInviteGate_AStaleTokenFallsBackToTheAddress(t *testing.T) {
	m := &signupTokenMock{
		tokenErr:  status.Error(codes.NotFound, "GetPendingOrgInviteByToken: no rows"),
		byAddress: []*pb.PendingInviteRow{{OrgId: "org-1"}},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}

	if err := requirePendingInvite(context.Background(), h, "her@corp.example", "an-expired-link"); err != nil {
		t.Fatalf("a legitimately invited address was refused because the link it also carried was stale: %v", err)
	}
}

// dupeMock refuses the write the way the storage tier does when the partial
// unique index on (org_id, email) already holds a live invitation: an
// InvalidArgument carrying a w17.ErrorDetail whose `code` is the discrimination.
type dupeMock struct {
	mintMock
}

func (m *dupeMock) CreateOrgInvite(_ context.Context, _ *pb.CreateOrgInviteReq, _ ...grpc.CallOption) (*pb.CreateOrgInviteResp, error) {
	st := status.New(codes.InvalidArgument, "constraint violation")
	// Exactly what the generated constraint registry carries for this index:
	//   "auth_orginvite_org_id_email_uidx":
	//       {Field: "", Code: "UNIQUE_VIOLATION", Message: "already exists"}
	// A composite index names no single field, so Field is empty — that is
	// information, not a gap.
	with, err := st.WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{
		Field: "", Code: "UNIQUE_VIOLATION", Message: "already exists",
	}))
	if err != nil {
		return nil, st.Err()
	}
	return nil, with.Err()
}

// The detail has to survive the hop.
//
// A consumer reported that a second invitation to the same address is
// indistinguishable from a malformed request, because both arrive as
// InvalidArgument. The top-level code IS uniform, deliberately — grpcerr
// collapses every validation-class violation so a client treats the class one
// way — and the discrimination lives in the detail's `code`.
//
// That argument only holds if the detail reaches the caller. The storage tier
// emits it (proved live by the e2e case on a composite index) and the gateway
// renders it, but nothing covered the middle: a BUSINESS handler returning a
// storage error onward. This is that link, and it is the one the answer to the
// report rests on.
func TestInviteToOrg_PropagatesTheConstraintDetail(t *testing.T) {
	m := &dupeMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	_, err := h.InviteToOrg(ctxWithCallerInOrg("u1", "org-1"), &pb.InviteToOrgReq{
		Email: "taken@corp.example", Role: "member",
	})
	if err == nil {
		t.Fatal("a duplicate invitation was accepted")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status error: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %s, want InvalidArgument (the class is deliberately uniform)", st.Code())
	}
	var codeSeen string
	for _, d := range st.Details() {
		if det, isDetail := d.(*w17pb.ErrorDetail); isDetail {
			codeSeen = det.GetCode()
		}
	}
	if codeSeen != "UNIQUE_VIOLATION" {
		t.Fatalf("the constraint detail did not survive the business handler — "+
			"a client then has only InvalidArgument and cannot tell a duplicate from a "+
			"malformed field, which is exactly what was reported. details = %v", st.Details())
	}
}

// The first registration through an OPEN link spends it on its address: the
// invitation is bound to it, and the same link admits nobody else after.
// Before, the link was only read here and one open link registered any number
// of accounts until somebody accepted it.
func TestClaimOpenInvite_TheFirstRegistrationSpendsTheLink(t *testing.T) {
	m := &signupTokenMock{} // open invitation
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}

	if err := claimOpenInvite(context.Background(), h, "first@example.com", "the-link"); err != nil {
		t.Fatalf("the first registration through an open link: %v", err)
	}
	if len(m.binds) != 1 || m.binds[0].GetEmail() != "first@example.com" || m.binds[0].GetTokenHash() != sha256Hex("the-link") {
		t.Fatalf("binds = %+v, want the link bound to first@example.com", m.binds)
	}
	// The second — the gate (read-only) still lets it through, the claim does not.
	if err := requirePendingInvite(context.Background(), h, "second@example.com", "the-link"); err == nil {
		t.Error("the gate admitted a second address through a link already bound to the first")
	}
	if err := claimOpenInvite(context.Background(), h, "second@example.com", "the-link"); err == nil {
		t.Fatal("a second registration through a spent link was admitted under invite_only")
	}
}

// Two registrations racing on one link both pass the gate; the claim decides.
// The loser is refused — unless its address holds an invitation of its own.
func TestClaimOpenInvite_TheLoserOfARaceKeepsItsOwnInvitation(t *testing.T) {
	m := &signupTokenMock{pendingEmail: "winner@example.com", byAddress: []*pb.PendingInviteRow{{OrgId: "org-2"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m, InviteOnly: true}
	if err := claimOpenInvite(context.Background(), h, "loser@example.com", "the-link"); err != nil {
		t.Fatalf("an address invited in its own right was refused because it lost the race on a link: %v", err)
	}
}

// Without invite_only an invitation only decides the org: the link is still
// spent, but a registration is never refused over it.
func TestClaimOpenInvite_WithoutInviteOnlyNothingIsRefused(t *testing.T) {
	m := &signupTokenMock{pendingEmail: "winner@example.com"}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if err := claimOpenInvite(context.Background(), h, "other@example.com", "the-link"); err != nil {
		t.Fatalf("registration is open, and was refused: %v", err)
	}
	if len(m.binds) != 1 {
		t.Errorf("the link was not offered for binding: %+v", m.binds)
	}
	if err := claimOpenInvite(context.Background(), h, "x@example.com", ""); err != nil || len(m.binds) != 1 {
		t.Errorf("a registration with no link claimed something: %v %+v", err, m.binds)
	}
}
