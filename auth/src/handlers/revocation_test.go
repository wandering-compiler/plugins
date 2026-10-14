package handlers

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Revocation is a state (device/revocation-is-a-state): every path that used
// to DELETE a token, a user or an auth client now writes revoked_at (and for a
// token revoked_by and revoke_reason), the row stays, and every resolver
// refuses a revoked token exactly as it refuses an expired one.
//
// revocationStore is the UserToken, Device and User tables as the revoking
// statements keep them: each fake method applies its statement's predicates
// (`revoked_at IS NULL` guards, the ownership conjuncts, the live lookup's
// `expires_at` + `revoked_at` filters, the miss-path lookup's
// expired-OR-revoked) and writes what its SET writes. It cannot prove the SQL
// — revocation_statements_test.go pins the statement text — but it proves that
// the handlers send each path through the right statement with the right
// actor, and what the refusal looks like afterwards.

type tokenRow struct {
	id, userID, hash, deviceID string
	kind                       pb.TokenType
	expiresAt, revokedAt       *timestamppb.Timestamp
	revokedBy                  string
	reason                     pb.RevokeReason
}

type deviceRow struct {
	id, userID, thumb, label, ip string
	revokedAt                    *timestamppb.Timestamp
}

type userRow struct {
	id, email, hash                         string
	disabledAt, erasedAt, trustRevokedAtCol *timestamppb.Timestamp
}

type revocationStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	tokens  map[string]*tokenRow
	devices map[string]*deviceRow
	users   map[string]*userRow

	// resetTokens: sha256 of a live reset link → its account.
	resetTokens map[string]string

	// The feature-owned erasure statements, by name and user.
	erased []string
	// RevokeUserToken / RevokeSessionToken calls that matched a row — the
	// ones whose event fires.
	emitted []string
}

func newRevocationStore() *revocationStore {
	return &revocationStore{
		tokens:      map[string]*tokenRow{},
		devices:     map[string]*deviceRow{},
		users:       map[string]*userRow{},
		resetTokens: map[string]string{},
	}
}

// now is the database clock (NOW()).
func now() *timestamppb.Timestamp { return timestamppb.Now() }

func (s *revocationStore) addUser(id, email string) *userRow {
	u := &userRow{id: id, email: email, hash: "$argon2id$placeholder"}
	s.users[id] = u
	return u
}

func (s *revocationStore) addDevice(id, userID, thumb string) *deviceRow {
	d := &deviceRow{id: id, userID: userID, thumb: thumb, label: "Firefox on Linux", ip: "203.0.113.7"}
	s.devices[id] = d
	return d
}

// addToken stores a live token presented as `bearer`, bound to deviceID ("" =
// none), expiring in an hour (nil for an API token that never expires).
func (s *revocationStore) addToken(id, userID, bearer, deviceID string, kind pb.TokenType) *tokenRow {
	t := &tokenRow{id: id, userID: userID, hash: sha256Hex(bearer), deviceID: deviceID, kind: kind}
	if kind == pb.TokenType_TOKEN_TYPE_SESSION {
		t.expiresAt = timestamppb.New(time.Now().Add(time.Hour))
	}
	s.tokens[id] = t
	return t
}

func (s *revocationStore) byHash(hash string) *tokenRow {
	for _, t := range s.tokens {
		if t.hash == hash {
			return t
		}
	}
	return nil
}

// live is the live lookups' predicate: (expires_at IS NULL OR expires_at >
// NOW()) AND revoked_at IS NULL.
func live(t *tokenRow) bool {
	return (t.expiresAt == nil || t.expiresAt.AsTime().After(time.Now())) && t.revokedAt == nil
}

// ended is the miss-path lookups' predicate: expires_at <= NOW() OR
// revoked_at IS NOT NULL.
func ended(t *tokenRow) bool {
	return (t.expiresAt != nil && !t.expiresAt.AsTime().After(time.Now())) || t.revokedAt != nil
}

func (s *revocationStore) binding(t *tokenRow) (thumb string, revokedAt *timestamppb.Timestamp) {
	if d, ok := s.devices[t.deviceID]; ok {
		return d.thumb, d.revokedAt
	}
	return "", nil
}

// revoke is the SET every revoking statement writes, under its
// `revoked_at IS NULL` guard: false when the row was already revoked.
func revoke(t *tokenRow, by string, reason pb.RevokeReason) bool {
	if t.revokedAt != nil {
		return false
	}
	t.revokedAt, t.revokedBy, t.reason = now(), by, reason
	return true
}

func notFound() error { return status.Error(codes.NotFound, "no rows") }

// ── the lookups ────────────────────────────────────────────────────────────

func (s *revocationStore) userOf(id string) *pb.User {
	u := s.users[id]
	if u == nil {
		return &pb.User{Id: id}
	}
	return &pb.User{Id: u.id, Email: u.email, PasswordHash: u.hash, DisabledAt: u.disabledAt, ErasedAt: u.erasedAt}
}

func (s *revocationStore) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	t := s.byHash(in.GetTokenHash())
	if t == nil || !live(t) {
		return nil, notFound()
	}
	thumb, devRevoked := s.binding(t)
	return &pb.GetTokenWithTypeResp{
		UserId: t.userID, TokenId: t.id, TokenType: t.kind, StoredTokenHash: t.hash,
		User: s.userOf(t.userID), DeviceThumbprint: thumb, DeviceRevokedAt: devRevoked,
	}, nil
}

func (s *revocationStore) GetExpiredTokenWithType(_ context.Context, in *pb.GetExpiredTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	t := s.byHash(in.GetTokenHash())
	if t == nil || !ended(t) {
		return nil, notFound()
	}
	thumb, devRevoked := s.binding(t)
	return &pb.GetExpiredTokenWithTypeResp{
		ExpiresAt: t.expiresAt, TokenType: t.kind, DeviceThumbprint: thumb,
		RevokedAt: t.revokedAt, DeviceRevokedAt: devRevoked,
	}, nil
}

func (s *revocationStore) GetUserByTokenWithPermissions(_ context.Context, in *pb.GetUserByTokenWithPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	t := s.byHash(in.GetTokenHash())
	if t == nil || !live(t) {
		return nil, notFound()
	}
	thumb, devRevoked := s.binding(t)
	return &pb.GetUserByTokenWithPermissionsResp{
		User: s.userOf(t.userID), TokenId: t.id, StoredTokenHash: t.hash,
		DeviceThumbprint: thumb, DeviceRevokedAt: devRevoked,
	}, nil
}

func (s *revocationStore) GetExpiredToken(_ context.Context, in *pb.GetExpiredTokenReq, _ ...grpc.CallOption) (*pb.GetExpiredTokenResp, error) {
	t := s.byHash(in.GetTokenHash())
	if t == nil || !ended(t) {
		return nil, notFound()
	}
	thumb, devRevoked := s.binding(t)
	return &pb.GetExpiredTokenResp{
		ExpiresAt: t.expiresAt, DeviceThumbprint: thumb, RevokedAt: t.revokedAt, DeviceRevokedAt: devRevoked,
	}, nil
}

func (s *revocationStore) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

func (s *revocationStore) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	return &pb.GetTokenPermissionSubsetResp{}, nil
}

func (s *revocationStore) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (s *revocationStore) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	if s.users[in.GetUserId()] == nil {
		return nil, notFound()
	}
	return &pb.GetUserByIdResp{User: s.userOf(in.GetUserId())}, nil
}

func (s *revocationStore) GetUserByEmail(_ context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	for _, u := range s.users {
		if u.email == in.GetEmail() {
			return &pb.GetUserByEmailResp{User: s.userOf(u.id)}, nil
		}
	}
	return nil, notFound()
}

// ListUserDevices: `revoked_at IS NULL AND thumbprint IS NOT NULL`.
func (s *revocationStore) ListUserDevices(_ context.Context, in *pb.ListUserDevicesReq, _ ...grpc.CallOption) (*pb.ListUserDevicesResp, error) {
	var out []*pb.Device
	for _, d := range s.devices {
		if d.userID == in.GetUserId() && d.revokedAt == nil && d.thumb != "" {
			out = append(out, &pb.Device{Id: d.id, UserId: d.userID, Thumbprint: d.thumb})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetId() < out[j].GetId() })
	return &pb.ListUserDevicesResp{Devices: out}, nil
}

// ListApiTokensByUser lists revoked tokens too, with when and why.
func (s *revocationStore) ListApiTokensByUser(_ context.Context, in *pb.ListApiTokensByUserReq, _ ...grpc.CallOption) (*pb.ListApiTokensByUserResp, error) {
	var out []*pb.ApiTokenInfo
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() && t.kind == in.GetTokenType() {
			out = append(out, &pb.ApiTokenInfo{Id: t.id, ExpiresAt: t.expiresAt, RevokedAt: t.revokedAt, RevokeReason: t.reason})
		}
	}
	return &pb.ListApiTokensByUserResp{Tokens: out}, nil
}

// ── the revoking statements ────────────────────────────────────────────────

func (s *revocationStore) TouchTokenLastUsed(context.Context, *pb.TouchTokenLastUsedReq, ...grpc.CallOption) (*pb.TouchTokenLastUsedResp, error) {
	return &pb.TouchTokenLastUsedResp{}, nil
}

func (s *revocationStore) UpgradeTokenHash(context.Context, *pb.UpgradeTokenHashReq, ...grpc.CallOption) (*pb.UpgradeTokenHashResp, error) {
	return &pb.UpgradeTokenHashResp{}, nil
}

// RevokeSessionToken: id AND user_id AND revoked_at IS NULL; by = user_id.
func (s *revocationStore) RevokeSessionToken(_ context.Context, in *pb.RevokeSessionTokenReq, _ ...grpc.CallOption) (*pb.RevokeSessionTokenResp, error) {
	t := s.tokens[in.GetTokenId()]
	if t == nil || t.userID != in.GetUserId() || !revoke(t, in.GetUserId(), pb.RevokeReason_REVOKE_REASON_LOGOUT) {
		return nil, notFound()
	}
	s.emitted = append(s.emitted, "TokenRevoked:"+t.id)
	return &pb.RevokeSessionTokenResp{TokenId: t.id, UserId: t.userID}, nil
}

// MarkApiTokenRevoked: id AND user_id AND token_type AND revoked_at IS NULL.
func (s *revocationStore) MarkApiTokenRevoked(_ context.Context, in *pb.MarkApiTokenRevokedReq, _ ...grpc.CallOption) (*pb.MarkApiTokenRevokedResp, error) {
	t := s.tokens[in.GetTokenId()]
	if t == nil || t.userID != in.GetUserId() || t.kind != in.GetTokenType() ||
		!revoke(t, in.GetUserId(), pb.RevokeReason_REVOKE_REASON_API_TOKEN_REVOKED) {
		return nil, notFound()
	}
	return &pb.MarkApiTokenRevokedResp{TokenId: t.id}, nil
}

// RevokeOtherSessionTokens: user_id AND id <> keep AND token_type = SESSION.
func (s *revocationStore) RevokeOtherSessionTokens(_ context.Context, in *pb.RevokeOtherSessionTokensReq, _ ...grpc.CallOption) (*pb.RevokeOtherSessionTokensResp, error) {
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() && t.id != in.GetKeepTokenId() && t.kind == pb.TokenType_TOKEN_TYPE_SESSION {
			revoke(t, in.GetUserId(), pb.RevokeReason_REVOKE_REASON_PASSWORD_CHANGED)
		}
	}
	return &pb.RevokeOtherSessionTokensResp{}, nil
}

// RevokeTokensForReset: every token of the user; by = NULL.
func (s *revocationStore) RevokeTokensForReset(_ context.Context, in *pb.RevokeTokensForResetReq, _ ...grpc.CallOption) (*pb.RevokeTokensForResetResp, error) {
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() {
			revoke(t, "", pb.RevokeReason_REVOKE_REASON_PASSWORD_RESET)
		}
	}
	return &pb.RevokeTokensForResetResp{}, nil
}

// RevokeDeviceTokens: user_id AND device_id; by = user_id.
func (s *revocationStore) RevokeDeviceTokens(_ context.Context, in *pb.RevokeDeviceTokensReq, _ ...grpc.CallOption) (*pb.RevokeDeviceTokensResp, error) {
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() && t.deviceID == in.GetDeviceId() {
			revoke(t, in.GetUserId(), pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
		}
	}
	return &pb.RevokeDeviceTokensResp{}, nil
}

// RevokeUndevicedSessions: user_id AND device_id IS NULL AND id <> keep AND
// token_type = SESSION; by = user_id.
func (s *revocationStore) RevokeUndevicedSessions(_ context.Context, in *pb.RevokeUndevicedSessionsReq, _ ...grpc.CallOption) (*pb.RevokeUndevicedSessionsResp, error) {
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() && t.deviceID == "" && t.id != in.GetKeepTokenId() && t.kind == pb.TokenType_TOKEN_TYPE_SESSION {
			revoke(t, in.GetUserId(), pb.RevokeReason_REVOKE_REASON_UNBOUND_SESSION)
		}
	}
	return &pb.RevokeUndevicedSessionsResp{}, nil
}

// MarkDeviceRevoked: id AND user_id AND revoked_at IS NULL.
func (s *revocationStore) MarkDeviceRevoked(_ context.Context, in *pb.MarkDeviceRevokedReq, _ ...grpc.CallOption) (*pb.MarkDeviceRevokedResp, error) {
	d := s.devices[in.GetDeviceId()]
	if d == nil || d.userID != in.GetUserId() || d.revokedAt != nil {
		return nil, notFound()
	}
	d.revokedAt = now()
	return &pb.MarkDeviceRevokedResp{DeviceId: d.id}, nil
}

// RevokeUserToken: id AND revoked_at IS NULL; by = :revoked_by.
func (s *revocationStore) RevokeUserToken(_ context.Context, in *pb.RevokeUserTokenReq, _ ...grpc.CallOption) (*pb.RevokeUserTokenResp, error) {
	t := s.tokens[in.GetId()]
	if t == nil || !revoke(t, in.GetRevokedBy(), pb.RevokeReason_REVOKE_REASON_ADMIN_REVOKED) {
		return nil, notFound()
	}
	s.emitted = append(s.emitted, "UserTokenRevoked:"+t.id)
	return &pb.RevokeUserTokenResp{TokenId: t.id}, nil
}

// DisableUsers: disabled_at on the active rows of the id set, then every
// token of the id set revoked (by NULL).
func (s *revocationStore) DisableUsers(_ context.Context, in *pb.DisableUsersReq, _ ...grpc.CallOption) (*pb.DisableUsersResp, error) {
	ids := map[string]bool{}
	for _, id := range in.GetIds() {
		ids[id] = true
		if u := s.users[id]; u != nil && u.disabledAt == nil {
			u.disabledAt = now()
		}
	}
	for _, t := range s.tokens {
		if ids[t.userID] {
			revoke(t, "", pb.RevokeReason_REVOKE_REASON_USER_DISABLED)
		}
	}
	return &pb.DisableUsersResp{}, nil
}

// EnableUsers: disabled_at = NULL WHERE disabled AND erased_at IS NULL.
func (s *revocationStore) EnableUsers(_ context.Context, in *pb.EnableUsersReq, _ ...grpc.CallOption) (*pb.EnableUsersResp, error) {
	for _, id := range in.GetIds() {
		if u := s.users[id]; u != nil && u.disabledAt != nil && u.erasedAt == nil {
			u.disabledAt = nil
		}
	}
	return &pb.EnableUsersResp{}, nil
}

// BeginUserErasure: tokens, devices, device details, disable, then the
// unusable password and the end of device trust. Idempotent.
func (s *revocationStore) BeginUserErasure(_ context.Context, in *pb.BeginUserErasureReq, _ ...grpc.CallOption) (*pb.BeginUserErasureResp, error) {
	for _, t := range s.tokens {
		if t.userID == in.GetUserId() {
			revoke(t, in.GetRevokedBy(), pb.RevokeReason_REVOKE_REASON_USER_ERASED)
		}
	}
	for _, d := range s.devices {
		if d.userID == in.GetUserId() {
			if d.revokedAt == nil {
				d.revokedAt = now()
			}
			d.label, d.ip = "", ""
		}
	}
	u := s.users[in.GetUserId()]
	if u == nil {
		return nil, notFound()
	}
	if u.disabledAt == nil {
		u.disabledAt = now()
	}
	u.hash, u.trustRevokedAtCol = "!", now()
	return &pb.BeginUserErasureResp{UserId: u.id}, nil
}

// EraseUser: the address and erased_at, guarded on erased_at IS NULL.
func (s *revocationStore) EraseUser(_ context.Context, in *pb.EraseUserReq, _ ...grpc.CallOption) (*pb.EraseUserResp, error) {
	u := s.users[in.GetUserId()]
	if u == nil || u.erasedAt != nil {
		return nil, notFound()
	}
	u.email, u.erasedAt = in.GetEmail(), now()
	return &pb.EraseUserResp{UserId: u.id}, nil
}

func (s *revocationStore) EraseOAuthData(_ context.Context, in *pb.EraseOAuthDataReq, _ ...grpc.CallOption) (*pb.EraseOAuthDataResp, error) {
	s.erased = append(s.erased, "oauth:"+in.GetUserId())
	return &pb.EraseOAuthDataResp{}, nil
}

func (s *revocationStore) EraseTwoFactorData(_ context.Context, in *pb.EraseTwoFactorDataReq, _ ...grpc.CallOption) (*pb.EraseTwoFactorDataResp, error) {
	s.erased = append(s.erased, "two_factor:"+in.GetUserId())
	return &pb.EraseTwoFactorDataResp{}, nil
}

func (s *revocationStore) SpendEmailVerificationTokens(_ context.Context, in *pb.SpendEmailVerificationTokensReq, _ ...grpc.CallOption) (*pb.SpendEmailVerificationTokensResp, error) {
	s.erased = append(s.erased, "email_verification:"+in.GetUserId())
	return &pb.SpendEmailVerificationTokensResp{}, nil
}

func (s *revocationStore) EraseOrgInviteAddress(_ context.Context, in *pb.EraseOrgInviteAddressReq, _ ...grpc.CallOption) (*pb.EraseOrgInviteAddressResp, error) {
	s.erased = append(s.erased, "org_invite:"+in.GetEmail())
	return &pb.EraseOrgInviteAddressResp{}, nil
}

func (s *revocationStore) ErasePendingSignUpAddress(_ context.Context, in *pb.ErasePendingSignUpAddressReq, _ ...grpc.CallOption) (*pb.ErasePendingSignUpAddressResp, error) {
	s.erased = append(s.erased, "sign_up_confirmation:"+in.GetEmail()+">"+in.GetPlaceholder())
	return &pb.ErasePendingSignUpAddressResp{}, nil
}

func (s *revocationStore) SpendPasswordResetTokens(_ context.Context, in *pb.SpendPasswordResetTokensReq, _ ...grpc.CallOption) (*pb.SpendPasswordResetTokensResp, error) {
	for hash, uid := range s.resetTokens {
		if uid == in.GetUserId() {
			delete(s.resetTokens, hash) // the fake's "consumed_at = NOW()"
		}
	}
	s.erased = append(s.erased, "password_reset:"+in.GetUserId())
	return &pb.SpendPasswordResetTokensResp{}, nil
}

// ── the password writes ChangePassword and ResetPassword run ────────────────

func (s *revocationStore) UpdateUserPasswordIfUnchanged(_ context.Context, in *pb.UpdateUserPasswordIfUnchangedReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordIfUnchangedResp, error) {
	u := s.users[in.GetUserId()]
	if u == nil || u.hash != in.GetCurrentHash() {
		return nil, notFound()
	}
	u.hash = in.GetPasswordHash()
	return &pb.UpdateUserPasswordIfUnchangedResp{UserId: u.id}, nil
}

func (s *revocationStore) ConsumePasswordResetToken(_ context.Context, in *pb.ConsumePasswordResetTokenReq, _ ...grpc.CallOption) (*pb.ConsumePasswordResetTokenResp, error) {
	uid, ok := s.resetTokens[in.GetTokenHash()]
	if !ok {
		return nil, notFound()
	}
	delete(s.resetTokens, in.GetTokenHash())
	return &pb.ConsumePasswordResetTokenResp{UserId: uid}, nil
}

func (s *revocationStore) UpdateUserPassword(_ context.Context, in *pb.UpdateUserPasswordReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordResp, error) {
	if u := s.users[in.GetUserId()]; u != nil {
		u.hash = in.GetPasswordHash()
	}
	return &pb.UpdateUserPasswordResp{UserId: in.GetUserId()}, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// authenticateWith runs Authenticate for bearer with a proof by jkt, through
// the given resolver, with no decorators or narrowers (bareAuthenticate's
// reasons).
func authenticateWith(t *testing.T, h *AuthServiceHandler, resolver func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error), bearer, jkt string) error {
	t.Helper()
	prevDec, prevNarrow, prevRes := scopeDecorators, grantNarrowers, resolvePrincipal
	t.Cleanup(func() { scopeDecorators, grantNarrowers, resolvePrincipal = prevDec, prevNarrow, prevRes })
	scopeDecorators, grantNarrowers, resolvePrincipal = nil, nil, resolver
	h.HeaderName, h.Scheme = "Authorization", "Bearer"
	_, err := h.Authenticate(context.Background(), boundAuthReq(bearer, jkt))
	return err
}

// assertRefusedLikeExpired is the invariant's check. The revoked token is
// refused; a twin token — the same owner, kind and device, NOT revoked, but
// expired at the very instant the revoked one was revoked — is refused too;
// and the two refusals are the same status, byte for byte (code, message,
// ErrorDetail, ErrorInfo), for the key's holder and for anyone else. A revoked
// token's holder learns nothing an expired token's holder would not.
func assertRefusedLikeExpired(t *testing.T, s *revocationStore, h *AuthServiceHandler, tok *tokenRow, bearer string) {
	t.Helper()
	if tok.revokedAt == nil {
		t.Fatalf("token %s is not revoked", tok.id)
	}
	twinBearer := "twin-of-" + bearer
	twin := &tokenRow{
		id: "twin-" + tok.id, userID: tok.userID, hash: sha256Hex(twinBearer), deviceID: tok.deviceID,
		kind: tok.kind, expiresAt: tok.revokedAt,
	}
	s.tokens[twin.id] = twin
	defer delete(s.tokens, twin.id)

	for name, resolver := range resolvers {
		if name == "session" && tok.kind != pb.TokenType_TOKEN_TYPE_SESSION {
			continue // the base resolver exists only where every token is a session
		}
		for _, jkt := range []string{testJKT, otherJKT} {
			revokedErr := authenticateWith(t, h, resolver, bearer, jkt)
			expiredErr := authenticateWith(t, h, resolver, twinBearer, jkt)
			if revokedErr == nil {
				t.Fatalf("%s resolver, key %s: the revoked token %s authenticated", name, jkt[:4], tok.id)
			}
			if expiredErr == nil {
				t.Fatalf("%s resolver, key %s: the expired twin authenticated", name, jkt[:4])
			}
			got, want := status.Convert(revokedErr).Proto(), status.Convert(expiredErr).Proto()
			if !proto.Equal(got, want) {
				t.Errorf("%s resolver, key %s: a revoked token is refused differently from an expired one:\n revoked: %v\n expired: %v",
					name, jkt[:4], got, want)
			}
		}
	}
}

// assertRevoked checks the row is still there, revoked, by whom and why.
func assertRevoked(t *testing.T, s *revocationStore, id, by string, reason pb.RevokeReason) *tokenRow {
	t.Helper()
	tok := s.tokens[id]
	if tok == nil {
		t.Fatalf("token %s is gone — revocation must keep the row", id)
	}
	if tok.revokedAt == nil {
		t.Fatalf("token %s is not revoked", id)
	}
	if tok.revokedBy != by || tok.reason != reason {
		t.Errorf("token %s revoked by %q for %v, want by %q for %v", id, tok.revokedBy, tok.reason, by, reason)
	}
	return tok
}

func assertLive(t *testing.T, s *revocationStore, id string) {
	t.Helper()
	if tok := s.tokens[id]; tok == nil || tok.revokedAt != nil {
		t.Errorf("token %s was revoked; it must stay live", id)
	}
}

// aliceStore: alice (u1) with a device on testJKT, a session on it, a second
// session on another device, and an API token bound to the first device.
func aliceStore() *revocationStore {
	s := newRevocationStore()
	s.addUser("u1", "alice@example.com")
	s.addDevice("d1", "u1", testJKT)
	s.addDevice("d2", "u1", otherJKT)
	s.addToken("t-session", "u1", "alice-session", "d1", pb.TokenType_TOKEN_TYPE_SESSION)
	s.addToken("t-other", "u1", "alice-other", "d2", pb.TokenType_TOKEN_TYPE_SESSION)
	s.addToken("t-api", "u1", "alice-api", "d1", pb.TokenType_TOKEN_TYPE_API)
	return s
}

// ── every converted path ───────────────────────────────────────────────────

// Logout revokes the caller's session — the holder is the actor — and the row
// stays. It is then refused as an expired token is; a second logout of it is
// still a clean success and fires no second TokenRevoked.
func TestLogout_RevokesTheSessionAndKeepsTheRow(t *testing.T) {
	s := aliceStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if err := authenticateWith(t, h, resolvePrincipalRealmAware, "alice-session", testJKT); err != nil {
		t.Fatalf("the live session did not authenticate: %v", err)
	}
	if _, err := h.Logout(sessionCallerCtx("u1", "t-session"), &pb.LogoutReq{}); err != nil {
		t.Fatalf("logout: %v", err)
	}
	tok := assertRevoked(t, s, "t-session", "u1", pb.RevokeReason_REVOKE_REASON_LOGOUT)
	assertLive(t, s, "t-other")
	assertLive(t, s, "t-api")
	assertRefusedLikeExpired(t, s, h, tok, "alice-session")

	first := tok.revokedAt
	if _, err := h.Logout(sessionCallerCtx("u1", "t-session"), &pb.LogoutReq{}); err != nil {
		t.Fatalf("a second logout of the same session failed: %v", err)
	}
	if !proto.Equal(s.tokens["t-session"].revokedAt, first) || len(s.emitted) != 1 {
		t.Errorf("a second logout rewrote the revocation or emitted again: %v, events %v", s.tokens["t-session"].revokedAt, s.emitted)
	}
}

// RevokeApiToken revokes the caller's API token, the owner as the actor; it is
// then refused as an expired API token is ("create a new token").
func TestRevokeApiToken_RevokesAndKeepsTheRow(t *testing.T) {
	s := aliceStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeApiToken(sessionCallerCtx("u1", "t-session"), &pb.RevokeApiTokenReq{TokenId: "t-api"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	tok := assertRevoked(t, s, "t-api", "u1", pb.RevokeReason_REVOKE_REASON_API_TOKEN_REVOKED)
	assertLive(t, s, "t-session")
	assertRefusedLikeExpired(t, s, h, tok, "alice-api")

	// The owner's list still shows it, revoked.
	list, err := h.ListApiTokens(sessionCallerCtx("u1", "t-session"), &pb.ListApiTokensReq{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetTokens()) != 1 || list.GetTokens()[0].GetRevokedAt() == nil ||
		list.GetTokens()[0].GetRevokeReason() != pb.RevokeReason_REVOKE_REASON_API_TOKEN_REVOKED {
		t.Errorf("the revoked token is not listed as revoked: %v", list.GetTokens())
	}
	// Somebody else's token is not touched, and that is no error.
	s.addUser("u2", "bob@example.com")
	s.addToken("t-bob", "u2", "bob-api", "", pb.TokenType_TOKEN_TYPE_API)
	if _, err := h.RevokeApiToken(sessionCallerCtx("u1", "t-session"), &pb.RevokeApiTokenReq{TokenId: "t-bob"}); err != nil {
		t.Fatalf("revoking another user's token answered an error: %v", err)
	}
	assertLive(t, s, "t-bob")
}

// ChangePassword revokes every OTHER session (the person as the actor) and
// keeps the caller's own and the API tokens.
func TestChangePassword_RevokesTheOtherSessions(t *testing.T) {
	s := aliceStore()
	hash, err := testPasswordSettings().Hash("old-password")
	if err != nil {
		t.Fatal(err)
	}
	s.users["u1"].hash = hash
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	if _, err := h.ChangePassword(sessionCallerCtx("u1", "t-session"), &pb.ChangePasswordReq{
		CurrentPassword: "old-password", NewPassword: "new-password",
	}); err != nil {
		t.Fatalf("change: %v", err)
	}
	tok := assertRevoked(t, s, "t-other", "u1", pb.RevokeReason_REVOKE_REASON_PASSWORD_CHANGED)
	assertLive(t, s, "t-session")
	assertLive(t, s, "t-api")
	assertRefusedLikeExpired(t, s, h, tok, "alice-other")
}

// ResetPassword revokes every token of the account, API tokens included, with
// no actor (the link proves no identity).
func TestResetPassword_RevokesEveryToken(t *testing.T) {
	s := aliceStore()
	s.resetTokens[sha256Hex("reset-link")] = "u1"
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "reset-link", NewPassword: "new-password"})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !resp.GetSessionsRevoked() {
		t.Error("the reset reports its sessions not revoked")
	}
	for id, bearer := range map[string]string{"t-session": "alice-session", "t-other": "alice-other", "t-api": "alice-api"} {
		tok := assertRevoked(t, s, id, "", pb.RevokeReason_REVOKE_REASON_PASSWORD_RESET)
		assertRefusedLikeExpired(t, s, h, tok, bearer)
	}
}

// RevokeDevice revokes the device's tokens (the person as the actor) and the
// device. Its holder hears DEVICE_REVOKED — what a live token of a revoked
// device answers — exactly as for an expired token of that device.
func TestRevokeDevice_RevokesTheDevicesTokens(t *testing.T) {
	s := aliceStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeDevice(sessionCallerCtx("u1", "t-other"), &pb.RevokeDeviceReq{DeviceId: "d1"}); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	session := assertRevoked(t, s, "t-session", "u1", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertRevoked(t, s, "t-api", "u1", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-other")
	if s.devices["d1"].revokedAt == nil {
		t.Fatal("the device is not revoked")
	}
	assertRefusedLikeExpired(t, s, h, session, "alice-session")
	err := authenticateWith(t, h, resolvePrincipalRealmAware, "alice-session", testJKT)
	if d := detailOf(t, err); d.GetCode() != CodeDeviceRevoked {
		t.Errorf("the key's holder was told %v, want %s", d, CodeDeviceRevoked)
	}
}

// RevokeOtherDevices also ends the sessions bound to no device (reason
// UNBOUND_SESSION), keeping the caller's own.
func TestRevokeOtherDevices_RevokesUnboundSessions(t *testing.T) {
	s := aliceStore()
	s.addToken("t-unbound", "u1", "alice-unbound", "", pb.TokenType_TOKEN_TYPE_SESSION)
	h := &AuthServiceHandler{Query: s, Mutation: s}
	ctx := ctxOnDevice(t, "u1", "t-session", testJKT)
	if _, err := h.RevokeOtherDevices(ctx, &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatalf("revoke others: %v", err)
	}
	unbound := assertRevoked(t, s, "t-unbound", "u1", pb.RevokeReason_REVOKE_REASON_UNBOUND_SESSION)
	assertRevoked(t, s, "t-other", "u1", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-session")
	assertRefusedLikeExpired(t, s, h, unbound, "alice-unbound")
}

// The admin's revoke: the operator is the actor, the row stays and stays
// listed; revoking a revoked row is a no-op, not an error, and does not fire a
// second event.
func TestRevokeSessions_TheOperatorRevokesAndARevokedRowIsANoOp(t *testing.T) {
	s := aliceStore()
	s.addUser("admin", "ops@example.com")
	h := &AuthServiceHandler{Query: s, Mutation: s}
	ctx := sessionCallerCtx("admin", "t-admin")
	if _, err := h.RevokeSessions(ctx, &pb.RevokeSessionsReq{Ids: []string{"t-session"}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	tok := assertRevoked(t, s, "t-session", "admin", pb.RevokeReason_REVOKE_REASON_ADMIN_REVOKED)
	assertRefusedLikeExpired(t, s, h, tok, "alice-session")

	first := *tok
	if _, err := h.RevokeSessions(ctx, &pb.RevokeSessionsReq{Ids: []string{"t-session", "t-other"}}); err != nil {
		t.Fatalf("revoking an already revoked session failed: %v", err)
	}
	if !proto.Equal(tok.revokedAt, first.revokedAt) || tok.revokedBy != first.revokedBy || tok.reason != first.reason {
		t.Errorf("the second revoke rewrote the first: %+v, was %+v", tok, first)
	}
	assertRevoked(t, s, "t-other", "admin", pb.RevokeReason_REVOKE_REASON_ADMIN_REVOKED)
	if fmt.Sprint(s.emitted) != "[UserTokenRevoked:t-session UserTokenRevoked:t-other]" {
		t.Errorf("events = %v, want one per revocation that happened", s.emitted)
	}
	// An empty selection (the admin's "all rows") revokes nothing.
	if _, err := h.RevokeSessions(ctx, &pb.RevokeSessionsReq{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an empty selection answered %v, want InvalidArgument", err)
	}
}

// DisableUsers' token leg: every token of the account revoked, with no actor
// (the admin action binds the storage mutation). Refused as expired tokens
// are; re-enabling gives none of them back.
func TestDisableUsers_RevokesEveryTokenAndEnableGivesNoneBack(t *testing.T) {
	s := aliceStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := s.DisableUsers(context.Background(), &pb.DisableUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatal(err)
	}
	for id, bearer := range map[string]string{"t-session": "alice-session", "t-other": "alice-other", "t-api": "alice-api"} {
		tok := assertRevoked(t, s, id, "", pb.RevokeReason_REVOKE_REASON_USER_DISABLED)
		assertRefusedLikeExpired(t, s, h, tok, bearer)
	}
	if _, err := s.EnableUsers(context.Background(), &pb.EnableUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatal(err)
	}
	if err := authenticateWith(t, h, resolvePrincipalRealmAware, "alice-session", testJKT); err == nil {
		t.Error("a token revoked by the disable works again after re-enabling")
	}
}

// ── erasure ────────────────────────────────────────────────────────────────

// eraseHandler: the standalone build stages every feature file, so every
// feature's init() has registered its eraser.
func eraseHandler(s *revocationStore) *AuthServiceHandler {
	return &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
}

// Erasure pseudonymises in place: the row stays, its address is the
// placeholder, its password unusable, the account disabled, every token
// revoked (USER_ERASED, the operator as the actor), every device revoked and
// stripped of its label and address, the feature-owned data erased and the
// reset links spent — and every token is refused as an expired one.
func TestEraseUsers_PseudonymisesAndKeepsEveryRow(t *testing.T) {
	s := aliceStore()
	s.addUser("admin", "ops@example.com")
	s.resetTokens[sha256Hex("old-link")] = "u1"
	h := eraseHandler(s)
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}

	u := s.users["u1"]
	if u == nil {
		t.Fatal("the user row is gone — erasure must keep it")
	}
	if u.email != "erased-u1@erased.invalid" || u.hash != "!" || u.erasedAt == nil || u.disabledAt == nil || u.trustRevokedAtCol == nil {
		t.Errorf("user after erasure = %+v, want the placeholder address, the unusable hash, erased, disabled, trust ended", u)
	}
	for id, bearer := range map[string]string{"t-session": "alice-session", "t-other": "alice-other", "t-api": "alice-api"} {
		tok := assertRevoked(t, s, id, "admin", pb.RevokeReason_REVOKE_REASON_USER_ERASED)
		assertRefusedLikeExpired(t, s, h, tok, bearer)
	}
	for _, d := range s.devices {
		if d.revokedAt == nil || d.label != "" || d.ip != "" {
			t.Errorf("device %s after erasure = %+v, want revoked with no label or address", d.id, d)
		}
	}
	want := []string{
		"email_verification:u1", "oauth:u1", "org_invite:alice@example.com",
		"password_reset:u1", "sign_up_confirmation:alice@example.com>erased-u1@erased.invalid", "two_factor:u1",
	}
	got := append([]string(nil), s.erased...)
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("feature erasers ran %v, want %v", got, want)
	}
	if len(s.resetTokens) != 0 {
		t.Error("a reset link sent before the erasure is still live")
	}
}

// An erased account is refused at every sign-in path, and enabling it does not
// make it usable again.
func TestEraseUsers_TheAccountCannotSignInAnyMore(t *testing.T) {
	s := aliceStore()
	hash, err := testPasswordSettings().Hash("alice-password")
	if err != nil {
		t.Fatal(err)
	}
	s.users["u1"].hash = hash
	h := eraseHandler(s)
	prev := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = prev })
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}

	// Password sign-in, by the old address (gone) and by the placeholder (no
	// password verifies against `!`): the same opaque refusal as any wrong
	// credential.
	for _, email := range []string{"alice@example.com", "erased-u1@erased.invalid"} {
		_, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: email, Password: "alice-password"})
		if status.Code(err) != codes.Unauthenticated || detailOf(t, err).GetCode() != CodeInvalidCredentials {
			t.Errorf("sign-in as %s after erasure: %v, want the opaque invalid-credentials refusal", email, err)
		}
	}
	// Every path that issues a session to an existing account by id — the
	// second sign-in step, the OAuth exchange, the CLI exchange — runs
	// refuseUnsignableAccount, and an erased account is disabled for good.
	if err := refuseUnsignableAccount(context.Background(), h, "u1"); status.Code(err) != codes.Unauthenticated {
		t.Errorf("an erased account passed the account gates: %v", err)
	}
	if _, err := s.EnableUsers(context.Background(), &pb.EnableUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatal(err)
	}
	if s.users["u1"].disabledAt == nil {
		t.Fatal("EnableUsers re-enabled an erased account")
	}
	if err := refuseUnsignableAccount(context.Background(), h, "u1"); status.Code(err) != codes.Unauthenticated {
		t.Errorf("after EnableUsers an erased account passed the account gates: %v", err)
	}
}

// The old address is free again: a new sign-up with it succeeds.
func TestEraseUsers_TheAddressCanSignUpAgain(t *testing.T) {
	s := aliceStore()
	h := eraseHandler(s)
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	pinConsoleActivation(t)
	signup := newConfirmStore()
	for _, u := range s.users {
		signup.users[u.email] = &pb.User{Id: u.id, Email: u.email}
	}
	sh := &AuthServiceHandler{Query: signup, Mutation: signup, PasswordHash: testPasswordSettings()}
	if _, err := sh.SignUp(mintCtx(), &pb.SignUpReq{Email: "alice@example.com", Password: "pw-again"}); err != nil {
		t.Fatalf("signing up again with the erased address: %v", err)
	}
}

// A second erase changes nothing and is no error: EraseUser is not run again
// (erased_at is read first), the erasers run again and find nothing left, and
// the statement's own guard settles a race (NotFound is done).
func TestEraseUsers_IsIdempotent(t *testing.T) {
	s := aliceStore()
	h := eraseHandler(s)
	ctx := sessionCallerCtx("admin", "t-admin")
	if _, err := h.EraseUsers(ctx, &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	before := *s.users["u1"]
	counted := &countingErase{revocationStore: s}
	ch := &AuthServiceHandler{Query: counted, Mutation: counted}
	if _, err := ch.EraseUsers(sessionCallerCtx("admin2", "t-admin2"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("a second erase failed: %v", err)
	}
	after := s.users["u1"]
	if !proto.Equal(after.erasedAt, before.erasedAt) || after.email != before.email || counted.eraseUserCalls != 0 {
		t.Errorf("a second erase changed the account or ran EraseUser again (%d): %+v, was %+v", counted.eraseUserCalls, after, before)
	}
	assertRevoked(t, s, "t-session", "admin", pb.RevokeReason_REVOKE_REASON_USER_ERASED)

	// The race: the read saw a live account, the statement found it erased.
	s.users["u1"].erasedAt = nil // as the read would have seen it
	raced := &racedErase{revocationStore: s}
	rh := &AuthServiceHandler{Query: raced, Mutation: raced}
	if err := rh.eraseUser(ctx, "u1", "admin"); err != nil {
		t.Fatalf("an erasure that lost the race failed: %v", err)
	}

	if _, err := h.EraseUsers(ctx, &pb.EraseUsersReq{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an empty selection answered %v, want InvalidArgument", err)
	}
}

// countingErase counts EraseUser calls.
type countingErase struct {
	*revocationStore
	eraseUserCalls int
}

func (c *countingErase) EraseUser(ctx context.Context, in *pb.EraseUserReq, o ...grpc.CallOption) (*pb.EraseUserResp, error) {
	c.eraseUserCalls++
	return c.revocationStore.EraseUser(ctx, in, o...)
}

// racedErase answers EraseUser as the statement does when another operator
// erased the account between the read and the write.
type racedErase struct{ *revocationStore }

func (r *racedErase) EraseUser(context.Context, *pb.EraseUserReq, ...grpc.CallOption) (*pb.EraseUserResp, error) {
	return nil, notFound()
}

// Erasure in a transaction: one per account, committed; a failing eraser rolls
// the account's erasure back.
func TestEraseUsers_OneTransactionPerAccount(t *testing.T) {
	s := aliceStore()
	s.addUser("u2", "bob@example.com")
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: s, Mutation: s, DistTx: tx, Connection: "main"}
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1", "u2"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if len(tx.begun) != 2 || len(tx.committed) != 2 || len(tx.rolledBack) != 0 {
		t.Errorf("transactions: begun %v committed %v rolled back %v, want two committed", tx.begun, tx.committed, tx.rolledBack)
	}

	failing := &failingEraser{revocationStore: aliceStore()}
	tx = &recordingDistTx{}
	h = &AuthServiceHandler{Query: failing, Mutation: failing, DistTx: tx, Connection: "main"}
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err == nil {
		t.Fatal("a failed eraser was reported as an erasure")
	}
	if len(tx.committed) != 0 || len(tx.rolledBack) != 1 {
		t.Errorf("a failed eraser: committed %v rolled back %v, want one rollback", tx.committed, tx.rolledBack)
	}
}

type failingEraser struct{ *revocationStore }

func (failingEraser) EraseTwoFactorData(context.Context, *pb.EraseTwoFactorDataReq, ...grpc.CallOption) (*pb.EraseTwoFactorDataResp, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}
