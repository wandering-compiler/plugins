package handlers

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// A role may be handed out only by someone who holds EVERY permission it
// carries — the role ceiling.
//
// Without it, whoever may invite at all could mint an org-admin, and the
// invitee could then mint the next one: an endpoint ACL decides WHETHER a
// caller may grant, and nothing decided WHAT. Holding the role yourself is the
// common case and is covered by the same test — your own role's permissions
// are a subset of your own permissions by construction. A role you do not hold
// passes too, as long as you hold everything in it, which is what lets an
// administrator hand out narrower roles than their own.
//
// "What the caller holds" is the permission set Authenticate resolved for THIS
// request — after the realm, the active organization, an API token's subset
// and ownership have all had their say — read off the envelope the gateway
// threads in. Recomputing it here would be a second resolver that has to agree
// with the first one, and the day it did not, the ceiling would sit somewhere
// the access checks do not. An organization's owner resolves to every
// permission, so an owner seeded without roles can still bootstrap anyone.
//
// Checked at the moment of granting. An invitation's grant is written LATER,
// at accept, so the invitation also stores what the role carried when it was
// checked, and accept refuses a role that has since grown past it. A ceiling
// that later drops does not revoke what was granted under it — that is
// membership management, not this.
//
// Staged with `org_membership` and with `service_account`, each of which
// brings both things it reads: the AuthResp envelope (authenticate_turnkey) and
// the role catalogue (rbac). Its callers — a membership's role change
// (org_membership_role.go), org_invite (which requires org_membership) and
// service_account — have one or the other; it reads no organization.

// errRoleAboveCaller is the refusal. It names the rule, not the missing
// permissions: the list would describe the role's contents to someone who has
// just been told they may not hand it out.
var errRoleAboveCaller = errors.New("that role carries permissions you do not hold — a role can be granted only by someone who holds everything it grants")

// errCallerPermissionsUnknown is the refusal when the request carries no
// resolved permission set — a direct gRPC call past the gateway. Fails closed:
// "could not tell" must not read as "nothing to exceed".
var errCallerPermissionsUnknown = errors.New("the request carries no resolved permissions, so a role ceiling cannot be checked")

// errRoleMovedSinceInvite is the refusal at accept when the role is no longer
// the one the inviter was checked against. The invitation stays unspent (the
// accept rolls back), so the inviter can revoke it and send a new one.
var errRoleMovedSinceInvite = errors.New("this invitation's role has changed since it was sent — ask for a new invitation")

// grantableRoleIDs returns the ids of every role the caller may grant.
//
// One function for both questions — "which roles may I be offered" and "may I
// grant this one" — so a picker and the endpoint behind it cannot disagree.
func (h *AuthServiceHandler) grantableRoleIDs(ctx context.Context) (map[string]bool, error) {
	var who pb.AuthResp
	if err := principal.Envelope(ctx, &who); err != nil {
		return nil, status.Error(codes.PermissionDenied, errCallerPermissionsUnknown.Error())
	}
	held := make(map[int32]bool, len(who.GetPermissionIds()))
	for _, id := range who.GetPermissionIds() {
		held[id] = true
	}
	catalogue, err := h.roleCatalogue(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for id, carried := range catalogue {
		if carried != nil && allHeld(carried, held) {
			out[id] = true
		}
	}
	return out, nil
}

// roleCatalogue maps every role id to the permissions it carries, a wildcard
// expanded from the deployed lock the way Authenticate expands it.
//
// A wildcard with no lock to expand from maps to nil — unknowable, and every
// caller refuses it. An empty expansion would otherwise be a subset of
// anything, and the most powerful role would be the one anyone could hand out.
func (h *AuthServiceHandler) roleCatalogue(ctx context.Context) (map[string][]int32, error) {
	resp, err := h.Query.ListRoleGrants(ctx, &pb.ListRoleGrantsReq{})
	if err != nil {
		return nil, err
	}
	out := make(map[string][]int32, len(resp.GetGrants()))
	for _, g := range resp.GetGrants() {
		out[g.GetRoleId()] = expandRoleGrant(g, h.Lock)
	}
	return out, nil
}

// expandRoleGrant returns what a role carries — never nil for a role whose
// contents are known, nil for a wildcard that cannot be expanded.
//
// A wildcard over a lock that EXISTS but allocates nothing — a domain with no
// endpoint catalogue — is known: "everything" here is nothing, the empty list.
// GrantAll answers nil for both an absent lock and an empty one, and read as
// "cannot be expanded" that refused every acceptance of an invitation to an
// all_permissions role in such a domain, and wrote snapshots that never
// matched (reported by a consumer, 2026-10-06). nil stays for the case it
// means: no lock at all.
func expandRoleGrant(g *pb.RoleGrant, lock *acllock.Lock) []int32 {
	if g.GetAllPermissions() {
		if lock == nil {
			return nil
		}
		if ids := acllock.GrantAll(lock); ids != nil {
			return ids
		}
		return []int32{}
	}
	if g.GetPermissionIds() == nil {
		return []int32{}
	}
	return g.GetPermissionIds()
}

func allHeld(carried []int32, held map[int32]bool) bool {
	for _, id := range carried {
		if !held[id] {
			return false
		}
	}
	return true
}

// checkMayGrantRole refuses a role above the caller's ceiling, and otherwise
// returns the role's snapshot — what it carried at the moment it was checked —
// for a grant that is written later (an invitation) to be held to.
func (h *AuthServiceHandler) checkMayGrantRole(ctx context.Context, roleID string) (string, error) {
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return "", err
	}
	if !grantable[roleID] {
		return "", refusal(ctx, codes.PermissionDenied, errRoleAboveCaller.Error(),
			CodeRoleAboveCaller, "role", MsgRoleAboveCaller, nil)
	}
	catalogue, err := h.roleCatalogue(ctx)
	if err != nil {
		return "", err
	}
	return encodeRoleSnapshot(roleID, catalogue[roleID]), nil
}

// checkRoleWithinSnapshot is the accept half: the role about to be granted
// must be the same role, carrying nothing the snapshot did not.
//
// Narrower is fine — the inviter covered more than is now handed out. Wider is
// not, and neither is a different role under the same name.
func (h *AuthServiceHandler) checkRoleWithinSnapshot(ctx context.Context, roleID, snapshot string) error {
	snapRole, snapPerms, ok := decodeRoleSnapshot(snapshot)
	if !ok || snapRole != roleID {
		return status.Error(codes.FailedPrecondition, errRoleMovedSinceInvite.Error())
	}
	catalogue, err := h.roleCatalogue(ctx)
	if err != nil {
		return err
	}
	carried, known := catalogue[roleID]
	if !known || carried == nil || !allHeld(carried, snapPerms) {
		return status.Error(codes.FailedPrecondition, errRoleMovedSinceInvite.Error())
	}
	return nil
}

// encodeRoleSnapshot renders `<role id>:<sorted ids>`. Sorted so the same role
// always reads the same, which is what makes a stored value comparable by eye.
func encodeRoleSnapshot(roleID string, carried []int32) string {
	ids := append([]int32(nil), carried...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(int64(id), 10)
	}
	return roleID + ":" + strings.Join(parts, ",")
}

// decodeRoleSnapshot parses encodeRoleSnapshot. An empty or malformed value is
// not a snapshot (ok=false) — that includes every invitation made before the
// ceiling existed, which were never checked.
func decodeRoleSnapshot(s string) (roleID string, perms map[int32]bool, ok bool) {
	roleID, list, found := strings.Cut(s, ":")
	if !found || roleID == "" {
		return "", nil, false
	}
	perms = map[int32]bool{}
	if list == "" {
		return roleID, perms, true
	}
	for _, part := range strings.Split(list, ",") {
		id, err := strconv.ParseInt(part, 10, 32)
		if err != nil {
			return "", nil, false
		}
		perms[int32(id)] = true
	}
	return roleID, perms, true
}
