package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/grant/gen/pb"
)

// store is an in-memory GrantQuery / GrantMutation.
type store struct {
	pb.GrantQueryClient
	pb.GrantMutationClient
	envelopes []*pb.EnvelopeRow
}

func (s *store) InsertEnvelope(_ context.Context, in *pb.InsertEnvelopeReq, _ ...grpc.CallOption) (*pb.InsertEnvelopeResp, error) {
	id := "env-" + string(rune('a'+len(s.envelopes)))
	s.envelopes = append(s.envelopes, &pb.EnvelopeRow{Id: id, OrgId: in.GetOrgId(), Status: StatusProposed, DisplayName: in.GetDisplayName()})
	return &pb.InsertEnvelopeResp{Id: id}, nil
}

func (s *store) ApproveEnvelopeRow(_ context.Context, in *pb.ApproveEnvelopeRowReq, _ ...grpc.CallOption) (*pb.ApproveEnvelopeRowResp, error) {
	var target *pb.EnvelopeRow
	for _, e := range s.envelopes {
		if e.GetId() == in.GetId() && e.GetStatus() == StatusProposed {
			target = e
		}
	}
	if target == nil {
		return nil, status.Error(codes.NotFound, "not pending")
	}
	for _, e := range s.envelopes {
		if e.GetOrgId() == target.GetOrgId() && e.GetStatus() == StatusApproved {
			e.Status = StatusSuperseded
		}
	}
	target.Status = StatusApproved
	return &pb.ApproveEnvelopeRowResp{Id: target.GetId(), OrgId: target.GetOrgId()}, nil
}

func (s *store) GetApprovedEnvelope(_ context.Context, in *pb.GetApprovedEnvelopeReq, _ ...grpc.CallOption) (*pb.EnvelopeRow, error) {
	for _, e := range s.envelopes {
		if e.GetOrgId() == in.GetOrgId() && e.GetStatus() == StatusApproved {
			return e, nil
		}
	}
	return nil, status.Error(codes.NotFound, "none")
}

// as is a request from userID, acting in orgID ("" = realm-wide).
func as(userID, orgID string) context.Context {
	env := protowire.AppendTag(nil, 2, protowire.BytesType)
	env = protowire.AppendString(env, userID)
	pairs := []string{callerMetadataKey, base64.StdEncoding.EncodeToString(env)}
	if orgID != "" {
		pairs = append(pairs, "x-w17-scope-org_id", orgID)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

// An organization proposes; nothing is shown until the backoffice approves;
// a newer approval supersedes the older one; a co-brand host shows its
// organization's approved envelope and an unbound host shows none.
func TestEnvelopeLifecycle(t *testing.T) {
	s := &store{}
	h := &GrantServiceHandler{Query: s, Mutation: s, Lock: &acllock.Lock{Permissions: map[string]int{
		"GRANT_GRANT_SERVICE_APPROVE_ENVELOPE": 1, "GRANT_GRANT_SERVICE_BIND_HOST": 2}}}
	v1, err := h.ProposeEnvelope(as("admin", "org-acme"), &pb.ProposeEnvelopeReq{Fields: &pb.EnvelopeFields{DisplayName: "Acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := h.GetOrgEnvelope(context.Background(), &pb.GetOrgEnvelopeReq{OrgId: "org-acme"}); got.GetFound() {
		t.Fatal("a proposal is shown before it is approved")
	}
	if _, err := h.ApproveEnvelope(as("admin", "org-acme"), &pb.ApproveEnvelopeReq{Id: v1.GetId()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an organization approved its own envelope: err = %v", err)
	}
	if _, err := h.ApproveEnvelope(as("ops", ""), &pb.ApproveEnvelopeReq{Id: v1.GetId()}); err != nil {
		t.Fatal(err)
	}
	v2, _ := h.ProposeEnvelope(as("admin", "org-acme"), &pb.ProposeEnvelopeReq{Fields: &pb.EnvelopeFields{DisplayName: "Acme Inc."}})
	got, _ := h.GetOrgEnvelope(context.Background(), &pb.GetOrgEnvelopeReq{OrgId: "org-acme"})
	if !got.GetFound() || got.GetFields().GetDisplayName() != "Acme" {
		t.Errorf("shown = %+v, want the approved v1 while v2 waits", got)
	}
	if _, err := h.ApproveEnvelope(as("ops", ""), &pb.ApproveEnvelopeReq{Id: v2.GetId()}); err != nil {
		t.Fatal(err)
	}
	if s.envelopes[0].GetStatus() != StatusSuperseded {
		t.Errorf("v1 is %s after v2's approval, want superseded", s.envelopes[0].GetStatus())
	}
	if got, _ := h.GetOrgEnvelope(context.Background(), &pb.GetOrgEnvelopeReq{OrgId: "org-acme"}); got.GetFields().GetDisplayName() != "Acme Inc." {
		t.Errorf("after v2's approval the organization shows %+v", got)
	}
}

// Without the endpoint ACL nobody approves: the method is not in the lock.
func TestRealmOnlyNeedsTheACL(t *testing.T) {
	h := &GrantServiceHandler{Lock: &acllock.Lock{Permissions: map[string]int{}}}
	if _, err := h.ApproveEnvelope(as("anyone", ""), &pb.ApproveEnvelopeReq{Id: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("err = %v, want PermissionDenied", err)
	}
}

func TestCheckFields(t *testing.T) {
	ok := &pb.EnvelopeFields{DisplayName: "Acme", LogoLightUrl: "https://cdn.example.com/a.png", AccentColor: "#112233", VerifiedHost: "acme.example.com", WebsiteUrl: "http://localhost:3000"}
	if err := checkFields(ok); err != nil {
		t.Errorf("a sound envelope refused: %v", err)
	}
	for name, f := range map[string]*pb.EnvelopeFields{
		"no name":        {},
		"javascript url": {DisplayName: "A", WebsiteUrl: "javascript:alert(1)"},
		"plain http":     {DisplayName: "A", LogoLightUrl: "http://cdn.example.com/a.png"},
		"credentials":    {DisplayName: "A", SupportUrl: "https://u:p@example.com"},
		"colour":         {DisplayName: "A", AccentColor: "red"},
		"host":           {DisplayName: "A", VerifiedHost: "Not A Host"},
	} {
		if err := checkFields(f); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
}

func TestProposeNeedsAnOrganization(t *testing.T) {
	h := &GrantServiceHandler{}
	if _, err := h.ProposeEnvelope(as("u", ""), &pb.ProposeEnvelopeReq{Fields: &pb.EnvelopeFields{DisplayName: "A"}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
	if _, err := h.ProposeEnvelope(context.Background(), &pb.ProposeEnvelopeReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no caller: err = %v, want Unauthenticated", err)
	}
}

// raceMutation answers ApproveEnvelopeRow as the unique index does when
// another version of the organization was approved at the same moment.
type raceMutation struct{ pb.GrantMutationClient }

func (raceMutation) ApproveEnvelopeRow(context.Context, *pb.ApproveEnvelopeRowReq, ...grpc.CallOption) (*pb.ApproveEnvelopeRowResp, error) {
	return nil, status.Error(codes.AlreadyExists, "unique violation")
}

// The approval that loses the race is told so, not handed a storage error.
func TestApproveEnvelopeRace(t *testing.T) {
	h := &GrantServiceHandler{Mutation: raceMutation{}, Lock: &acllock.Lock{Permissions: map[string]int{"GRANT_GRANT_SERVICE_APPROVE_ENVELOPE": 1}}}
	if _, err := h.ApproveEnvelope(as("ops", ""), &pb.ApproveEnvelopeReq{Id: "x"}); status.Code(err) != codes.Aborted {
		t.Errorf("err = %v, want Aborted", err)
	}
}

// The backoffice may be a member of an organization: a request acting inside
// one whose credential holds the method realm-wide (the auth plugin's
// realm_permissions scope: `*`, or the ids) decides envelopes realm-wide. An
// organization's own admin, with no such role, is refused there as before,
// and so is a realm-wide role that does not carry the method.
func TestEnvelopeDecisions_TheBackofficeFromInsideAnOrganization(t *testing.T) {
	s := &store{}
	h := &GrantServiceHandler{Query: s, Mutation: s, Lock: &acllock.Lock{Permissions: map[string]int{
		"GRANT_GRANT_SERVICE_APPROVE_ENVELOPE": 1, "GRANT_GRANT_SERVICE_REJECT_ENVELOPE": 2, "GRANT_GRANT_SERVICE_LIST_ENVELOPE_PROPOSALS": 3}}}
	backoffice := func(orgID string) context.Context {
		ctx := as("ops", orgID)
		md, _ := metadata.FromIncomingContext(ctx)
		md = md.Copy()
		md.Set("x-w17-scope-realm_permissions", "*")
		return metadata.NewIncomingContext(context.Background(), md)
	}
	v1, err := h.ProposeEnvelope(as("admin", "org-acme"), &pb.ProposeEnvelopeReq{Fields: &pb.EnvelopeFields{DisplayName: "Acme"}})
	if err != nil {
		t.Fatal(err)
	}
	listed := func(ids string) context.Context {
		ctx := as("ops", "org-ops")
		md, _ := metadata.FromIncomingContext(ctx)
		md = md.Copy()
		md.Set("x-w17-scope-realm_permissions", ids)
		return metadata.NewIncomingContext(context.Background(), md)
	}
	if _, err := h.realmOnly(listed("1,3"), "ListEnvelopeProposals"); err != nil {
		t.Errorf("a realm-wide role listing ListEnvelopeProposals (3): %v", err)
	}
	if _, err := h.realmOnly(listed("1,3"), "RejectEnvelope"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a realm-wide role without RejectEnvelope (2): err = %v, want PermissionDenied", err)
	}
	for _, m := range []string{"ListEnvelopeProposals", "RejectEnvelope"} {
		if _, err := h.realmOnly(backoffice("org-ops"), m); err != nil {
			t.Errorf("the backoffice's %s from inside its own organization: %v", m, err)
		}
		if _, err := h.realmOnly(as("admin", "org-acme"), m); status.Code(err) != codes.PermissionDenied {
			t.Errorf("an organization's admin's %s: err = %v, want PermissionDenied", m, err)
		}
	}
	if _, err := h.ApproveEnvelope(as("admin", "org-acme"), &pb.ApproveEnvelopeReq{Id: v1.GetId()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an organization's admin approving its own envelope: err = %v, want PermissionDenied", err)
	}
	if _, err := h.ApproveEnvelope(backoffice("org-ops"), &pb.ApproveEnvelopeReq{Id: v1.GetId()}); err != nil {
		t.Errorf("the backoffice approving from inside its own organization: %v", err)
	}
}
