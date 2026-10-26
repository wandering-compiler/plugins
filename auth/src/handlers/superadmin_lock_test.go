package handlers

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// txOrder records, for a change that can take a superadmin away, the order of
// the organization's lock, the superadmin read and the write, each marked with
// whether the one transaction was open at the time.
type txOrder struct {
	tx    *recordingDistTx
	steps []string
}

func (o *txOrder) note(step string) {
	if len(o.tx.begun) == 1 && len(o.tx.committed) == 0 && len(o.tx.rolledBack) == 0 {
		step += " in tx"
	}
	o.steps = append(o.steps, step)
}

type lockedMembershipMock struct {
	*superadminMock
	*txOrder
}

func (m lockedMembershipMock) LockOrganization(ctx context.Context, in *pb.LockOrganizationReq, opts ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	m.note("lock " + in.GetOrgId())
	return m.superadminMock.LockOrganization(ctx, in, opts...)
}

func (m lockedMembershipMock) ListOrgSuperadmins(ctx context.Context, in *pb.ListOrgSuperadminsReq, opts ...grpc.CallOption) (*pb.ListOrgSuperadminsResp, error) {
	m.note("superadmins")
	return m.superadminMock.ListOrgSuperadmins(ctx, in, opts...)
}

func (m lockedMembershipMock) UpdateOrgMembership(ctx context.Context, in *pb.UpdateOrgMembershipReq, opts ...grpc.CallOption) (*pb.UpdateOrgMembershipResp, error) {
	m.note("write")
	return m.superadminMock.UpdateOrgMembership(ctx, in, opts...)
}

func (m lockedMembershipMock) MarkOrgMembershipRemoved(ctx context.Context, in *pb.MarkOrgMembershipRemovedReq, opts ...grpc.CallOption) (*pb.MarkOrgMembershipRemovedResp, error) {
	m.note("write")
	return m.superadminMock.MarkOrgMembershipRemoved(ctx, in, opts...)
}

type lockedTeamStore struct {
	*teamStore
	*txOrder
}

func (s lockedTeamStore) LockOrganization(ctx context.Context, in *pb.LockOrganizationReq, opts ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	s.note("lock " + in.GetOrgId())
	return s.teamStore.LockOrganization(ctx, in, opts...)
}

func (s lockedTeamStore) ListOrgSuperadmins(ctx context.Context, in *pb.ListOrgSuperadminsReq, opts ...grpc.CallOption) (*pb.ListOrgSuperadminsResp, error) {
	s.note("superadmins")
	return s.teamStore.ListOrgSuperadmins(ctx, in, opts...)
}

// What a team holds, noted only when read inside the transaction:
// SetOrgTeamRoles diffs against it under the lock, while the ceiling checks
// before the transaction (coverTeamRoles) read it too.
func (s lockedTeamStore) ListTeamRoleIds(ctx context.Context, in *pb.ListTeamRoleIdsReq, opts ...grpc.CallOption) (*pb.ListTeamRoleIdsResp, error) {
	if len(s.tx.begun) == 1 && len(s.tx.committed) == 0 && len(s.tx.rolledBack) == 0 {
		s.note("team roles")
	}
	return s.teamStore.ListTeamRoleIds(ctx, in, opts...)
}

func (s lockedTeamStore) DeleteTeam(ctx context.Context, in *pb.DeleteTeamReq, opts ...grpc.CallOption) (*pb.DeleteTeamResp, error) {
	s.note("write")
	return s.teamStore.DeleteTeam(ctx, in, opts...)
}

func (s lockedTeamStore) RemoveTeamMember(ctx context.Context, in *pb.RemoveTeamMemberReq, opts ...grpc.CallOption) (*pb.RemoveTeamMemberResp, error) {
	s.note("write")
	return s.teamStore.RemoveTeamMember(ctx, in, opts...)
}

func (s lockedTeamStore) RevokeTeamRole(ctx context.Context, in *pb.RevokeTeamRoleReq, opts ...grpc.CallOption) (*pb.RevokeTeamRoleResp, error) {
	s.note("write")
	return s.teamStore.RevokeTeamRole(ctx, in, opts...)
}

// Every change that can take a superadmin away locks the organization's row,
// reads its superadmins and writes, in that order and in ONE transaction. Two
// superadmins demoting each other at the same moment each passed a check made
// before the write's transaction — each still saw the other — and left the
// organization with none. Under the lock the second waits for the first, and
// its read sees what the first one ended. A refusal rolls back with nothing
// written.
func TestSuperadminChanges_CheckAndWriteUnderTheOrganizationsLock(t *testing.T) {
	want := []string{"lock org-1 in tx", "superadmins in tx", "write in tx"}

	membership := func(t *testing.T, do func(h *AuthServiceHandler, ctx context.Context) error) {
		t.Helper()
		self := inOrg(withHeldPermissions(context.Background(), "u2", 1, 2, 3), "org-1")
		for _, refused := range []bool{false, true} {
			_, mm := newMembershipRoleHandler("r-super")
			mm.all = append(mm.all, &pb.Role{Id: "r-super", Name: "org-super"})
			mm.orgScoped = append(mm.orgScoped, &pb.OrgScopedRole{Id: "r-super", Name: "org-super"})
			sm := &superadminMock{membershipRoleMock: mm}
			if !refused {
				sm.others = 1
			}
			order := &txOrder{tx: &recordingDistTx{}}
			m := lockedMembershipMock{superadminMock: sm, txOrder: order}
			h := &AuthServiceHandler{Query: m, Mutation: m, Lock: wildcardLock(), DistTx: order.tx, Connection: "main"}
			err := do(h, self)
			steps, settled := want, "committed"
			if refused {
				if detailOf(t, err).GetCode() != CodeLastSuperadmin {
					t.Fatalf("the last superadmin: %v", err)
				}
				if mm.updated != nil || mm.deleted != nil {
					t.Fatalf("a refused change wrote: updated=%v deleted=%v", mm.updated, mm.deleted)
				}
				steps, settled = want[:2], "rolled back"
			} else if err != nil {
				t.Fatalf("another superadmin remains: %v", err)
			}
			if !reflect.DeepEqual(order.steps, steps) || order.tx.settled() != settled {
				t.Fatalf("refused=%v: steps %q, transaction %s; want %q, %s", refused, order.steps, order.tx.settled(), steps, settled)
			}
		}
	}
	t.Run("UpdateOrgMembershipRole", func(t *testing.T) {
		membership(t, func(h *AuthServiceHandler, ctx context.Context) error {
			_, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-admin"})
			return err
		})
	})
	t.Run("RemoveOrgMembership", func(t *testing.T) {
		membership(t, func(h *AuthServiceHandler, ctx context.Context) error {
			_, err := h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"})
			return err
		})
	})

	for name, do := range map[string]func(h *AuthServiceHandler) error{
		"RemoveOrgTeamMember": func(h *AuthServiceHandler) error {
			_, err := h.RemoveOrgTeamMember(superCaller(), &pb.RemoveOrgTeamMemberReq{TeamId: "t-admin", UserId: "u3"})
			return err
		},
		"SetOrgTeamRoles": func(h *AuthServiceHandler) error {
			_, err := h.SetOrgTeamRoles(superCaller(), &pb.SetOrgTeamRolesReq{TeamId: "t-admin", RoleIds: []string{"r-viewer"}})
			return err
		},
		"DeleteOrgTeam": func(h *AuthServiceHandler) error {
			_, err := h.DeleteOrgTeam(superCaller(), &pb.DeleteOrgTeamReq{TeamId: "t-admin"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, refused := range []bool{false, true} {
				h, s := superTeams()
				if !refused {
					s.directSupers = []string{"u1"}
				}
				order := &txOrder{tx: &recordingDistTx{}}
				locked := lockedTeamStore{teamStore: s, txOrder: order}
				h.Query, h.Mutation, h.DistTx, h.Connection = locked, locked, order.tx, "main"
				err := do(h)
				// Every team method reads the team's roles under the lock: the
				// ceiling (coverTeamRoles) judges what the write changes, and
				// two SetOrgTeamRoles on one team cannot diff the same stale set.
				want := []string{want[0], "team roles in tx", want[1], want[2]}
				steps, settled := want, "committed"
				if refused {
					if detailOf(t, err).GetCode() != CodeLastSuperadmin {
						t.Fatalf("the last superadmin: %v", err)
					}
					steps, settled = want[:len(want)-1], "rolled back"
				} else if err != nil {
					t.Fatalf("another superadmin remains: %v", err)
				}
				if !reflect.DeepEqual(order.steps, steps) || order.tx.settled() != settled {
					t.Fatalf("refused=%v: steps %q, transaction %s; want %q, %s", refused, order.steps, order.tx.settled(), steps, settled)
				}
			}
		})
	}
}
