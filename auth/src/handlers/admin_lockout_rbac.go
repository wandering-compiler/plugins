package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file is staged when `user_admin` and `rbac` are both on (plugin.yaml
// go_files_combined): the last-admin rule needs the roles to know who
// administers the realm.

func init() {
	realmAdmins = listRealmAdmins
}

// listRealmAdmins is the realm's administrators who can act: the accounts of
// AuthQuery.ListRealmSuperadmins (a live grant of a live wildcard role), minus
// a disabled or erased account and an API-realm grant — a machine account's
// wildcard administers nothing through a session.
//
// Read, lock, read again. The JOIN-shaped read cannot carry a row lock, so
// the accounts it finds are locked (LockUsers, in id order) and the read is
// repeated under the lock: two operators disabling each other at once take
// the same rows in the same order, and the second one's second read sees the
// account the first one disabled. An administrator added between the reads is
// in the second one, which can only keep the realm administered.
func listRealmAdmins(ctx context.Context, h *AuthServiceHandler) ([]string, bool, error) {
	first, err := readRealmAdmins(ctx, h)
	if err != nil || len(first) == 0 {
		return first, true, err
	}
	if _, err := h.Query.LockUsers(ctx, &pb.LockUsersReq{Ids: first}); err != nil {
		return nil, true, err
	}
	ids, err := readRealmAdmins(ctx, h)
	return ids, true, err
}

// readRealmAdmins is one unlocked read of the administrators who can act.
func readRealmAdmins(ctx context.Context, h *AuthServiceHandler) ([]string, error) {
	resp, err := h.Query.ListRealmSuperadmins(ctx, &pb.ListRealmSuperadminsReq{})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, g := range resp.GetGrants() {
		if g.GetDisabledAt() != nil || g.GetErasedAt() != nil || isAPIRealmRow(g) || seen[g.GetUserId()] {
			continue
		}
		seen[g.GetUserId()] = true
		ids = append(ids, g.GetUserId())
	}
	return ids, nil
}
