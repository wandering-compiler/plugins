package handlers

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The statements behind device/revocation-is-a-state, read from the protos: a
// fake store cannot run SQL, so what the database is asked to do is pinned
// here, and revocation_test.go proves what the handlers do with it.

// dqlText is a proto with its comment lines removed and its adjacent string
// literals joined, so a statement split over several lines reads as one
// string, and a comment that merely mentions a DELETE does not count.
func dqlText(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return regexp.MustCompile(`"\s*\n\s*"`).ReplaceAllString(b.String(), "")
}

// rpcBodies splits a proto into its rpc declarations by name.
func rpcBodies(src string) map[string]string {
	out := map[string]string{}
	re := regexp.MustCompile(`rpc (\w+)\(`)
	for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		rest := src[m[0]:]
		if end := strings.Index(rest, "\n  }\n"); end > 0 {
			rest = rest[:end]
		}
		out[name] = rest
	}
	return out
}

func authProtos(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range []string{
		"types/models.proto", "queries/auth_query.proto", "mutations/auth_mutation.proto",
		"business/auth_service.proto", "events/auth_events.proto",
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "proto", rel))
		if err != nil {
			t.Fatal(err)
		}
		out[rel] = string(b)
	}
	return out
}

// The guard: nothing in the auth plugin deletes a token, a user, a device, an
// auth client, or the permission subset of a token. A statement that does is
// refused here whatever its name, so a new DELETE path cannot slip in under a
// name nobody thought to check.
func TestNoStatementDeletesTokensUsersDevicesOrClients(t *testing.T) {
	re := regexp.MustCompile(`(?i)DELETE\s+FROM\s+@module\.(UserToken|User|Device|AuthClient|TokenPermission)\b`)
	checked := 0
	for rel, src := range authProtos(t) {
		text := dqlText(src)
		checked += strings.Count(text, "dql:")
		for _, m := range re.FindAllString(text, -1) {
			t.Errorf("%s: %q — nothing in the auth tables is deleted; revoke (revoked_at) or pseudonymise instead", rel, m)
		}
	}
	if checked < 100 {
		t.Fatalf("read only %d statements — the guard is not looking at the protos", checked)
	}
	// The guard's own matcher, against the shapes it must catch and must not.
	for s, want := range map[string]bool{
		`"DELETE FROM @module.UserToken WHERE id = :id"`:     true,
		`"DELETE FROM @module.User WHERE id = :user_id"`:     true,
		`"delete from @module.AuthClient where id = :id"`:    true,
		`"DELETE FROM @module.UserRole WHERE user_id = :id"`: false,
		`"DELETE FROM @module.UserRecoveryCode WHERE x"`:     false,
	} {
		if re.MatchString(s) != want {
			t.Errorf("guard matcher on %s = %v, want %v", s, !want, want)
		}
	}
}

// Every lookup that reads a token as VALID refuses a revoked one beside the
// expiry, and the miss-path probes read exactly the rows those two predicates
// refuse — so a revoked token is answered as an expired one.
func TestEveryTokenLookupRefusesARevokedToken(t *testing.T) {
	queries := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	var lookups []string
	for name, body := range queries {
		if !strings.Contains(body, "@module.UserToken") || !strings.Contains(body, "t.expires_at > NOW()") {
			continue
		}
		lookups = append(lookups, name)
		if !strings.Contains(body, "(t.expires_at IS NULL OR t.expires_at > NOW()) AND t.revoked_at IS NULL") {
			t.Errorf("%s reads a token as valid without refusing a revoked one:\n%s", name, body)
		}
	}
	sort.Strings(lookups)
	want := "GetLiveSessionExpiry,GetTokenWithType,GetUserByToken,GetUserByTokenWithPermissions"
	if strings.Join(lookups, ",") != want {
		t.Errorf("token lookups = %v, want %s", lookups, want)
	}
	for _, probe := range []string{"GetExpiredToken", "GetExpiredTokenWithType"} {
		if !strings.Contains(queries[probe], "(t.expires_at <= NOW() OR t.revoked_at IS NOT NULL)") {
			t.Errorf("%s does not read revoked rows as ended:\n%s", probe, queries[probe])
		}
	}
	// The display lists keep revoked rows and say so.
	for name, cols := range map[string][]string{
		"ListUserTokens":      {"t.revoked_at AS revoked_at", "t.revoke_reason AS revoke_reason"},
		"GetUserToken":        {"t.revoked_at AS revoked_at", "t.revoked_by AS revoked_by", "t.revoke_reason AS revoke_reason"},
		"ListApiTokensByUser": {"t.revoked_at AS revoked_at", "t.revoke_reason AS revoke_reason"},
	} {
		body := queries[name]
		for _, c := range cols {
			if !strings.Contains(body, c) {
				t.Errorf("%s does not project %q:\n%s", name, c, body)
			}
		}
		if strings.Contains(body, "revoked_at IS NULL") {
			t.Errorf("%s hides revoked tokens; a display list shows them as revoked:\n%s", name, body)
		}
	}
}

// Every revocation of a token is an UPDATE that stamps revoked_at with NOW(),
// the reason its path stands for and the actor it has (or none), guarded on
// `revoked_at IS NULL` so the first revocation stands. The table lists every
// path; a new one has to be added here, with its reason.
func TestEveryTokenRevocationIsAGuardedUpdate(t *testing.T) {
	type want struct {
		reason pb.RevokeReason
		by     string // the :param stamped as revoked_by; "" = none (NULL)
	}
	paths := map[string]want{
		"RevokeToken":              {pb.RevokeReason_REVOKE_REASON_TOKEN_REVOKED, ""},
		"RevokeSessionToken":       {pb.RevokeReason_REVOKE_REASON_LOGOUT, ":user_id"},
		"MarkApiTokenRevoked":      {pb.RevokeReason_REVOKE_REASON_API_TOKEN_REVOKED, ":user_id"},
		"RevokeOtherSessionTokens": {pb.RevokeReason_REVOKE_REASON_PASSWORD_CHANGED, ":user_id"},
		"RevokeTokensForReset":     {pb.RevokeReason_REVOKE_REASON_PASSWORD_RESET, ""},
		"RevokeDeviceTokens":       {pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED, ":revoked_by"},
		"RevokeApprovedApiTokens":  {pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED, ":revoked_by"},
		"RevokeUndevicedSessions":  {pb.RevokeReason_REVOKE_REASON_UNBOUND_SESSION, ":user_id"},
		"RevokeAllUserTokens":      {pb.RevokeReason_REVOKE_REASON_ALL_TOKENS_REVOKED, ":user_id"},
		"RevokeUserToken":          {pb.RevokeReason_REVOKE_REASON_ADMIN_REVOKED, ":revoked_by"},
		"DisableUsers":             {pb.RevokeReason_REVOKE_REASON_USER_DISABLED, ""},
		"BeginUserErasure":         {pb.RevokeReason_REVOKE_REASON_USER_ERASED, ":revoked_by"},
	}
	setRe := regexp.MustCompile(`UPDATE @module\.UserToken SET revoked_at = NOW\(\), (?:revoked_by = (:\w+), )?revoke_reason = (\d+) WHERE ([^"]*)"`)
	seen := map[string]bool{}
	for name, body := range rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"])) {
		if !strings.Contains(body, "revoked_at = NOW()") || !strings.Contains(body, "@module.UserToken SET revoked_at") {
			continue
		}
		seen[name] = true
		w, ok := paths[name]
		if !ok {
			t.Errorf("%s revokes tokens and is not in this table — give it a reason here", name)
			continue
		}
		m := setRe.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("%s: the revocation is not `SET revoked_at = NOW(), [revoked_by = :x, ]revoke_reason = N WHERE …`:\n%s", name, body)
			continue
		}
		if m[1] != w.by {
			t.Errorf("%s stamps revoked_by %q, want %q", name, m[1], w.by)
		}
		n, _ := strconv.Atoi(m[2])
		if pb.RevokeReason(n) != w.reason {
			t.Errorf("%s stamps revoke_reason %d (%s), want %v", name, n, pb.RevokeReason_name[int32(n)], w.reason)
		}
		if !strings.Contains(m[3], "revoked_at IS NULL") {
			t.Errorf("%s is not guarded on `revoked_at IS NULL`, so a later revocation rewrites the first:\n%s", name, m[3])
		}
	}
	for name := range paths {
		if !seen[name] {
			t.Errorf("%s no longer revokes a token through an UPDATE", name)
		}
	}
	// No reason is stamped twice for different paths: each reason names one
	// cause. RevokeApprovedApiTokens is not another path — it runs beside
	// RevokeDeviceTokens in the same device revocation, for the API tokens
	// the device created — so it shares its reason.
	reasons := map[pb.RevokeReason]string{}
	for name, w := range paths {
		if name == "RevokeApprovedApiTokens" {
			continue
		}
		if other, dup := reasons[w.reason]; dup {
			t.Errorf("%s and %s share reason %v", name, other, w.reason)
		}
		reasons[w.reason] = name
	}
}

// Minting is one INSERT: the expired-session sweep is gone.
func TestIssueToken_SweepsNothing(t *testing.T) {
	body := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))["IssueToken"]
	if strings.Count(body, "dql:") != 1 || strings.Contains(body, "sweep") {
		t.Errorf("IssueToken is not the one INSERT:\n%s", body)
	}
}

// Erasure is UPDATEs only, pseudonymises the User row once, and nothing can
// turn the account back into a usable one.
func TestEraseStatements(t *testing.T) {
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	// The first step ends access and leaves the address alone.
	begin := m["BeginUserErasure"]
	for _, want := range []string{
		"UPDATE @module.Device SET revoked_at = NOW() WHERE user_id = :user_id AND revoked_at IS NULL",
		`UPDATE @module.Device SET label = \'\', ip = \'\' WHERE user_id = :user_id`,
		"UPDATE @module.User SET disabled_at = NOW() WHERE id = :user_id AND disabled_at IS NULL",
		`password_hash = \'!\', `,
		"device_trust_revoked_at = NOW() ",
		"?feature(email_verification) email_verified_at = NULL, ",
	} {
		if !strings.Contains(begin, want) {
			t.Errorf("BeginUserErasure lacks %q:\n%s", want, begin)
		}
	}
	if strings.Contains(begin, "email =") || strings.Contains(begin, "erased_at") {
		t.Errorf("BeginUserErasure touches the address or erased_at — that is the last step's:\n%s", begin)
	}
	// The last step replaces the address and stamps erased_at, once.
	erase := m["EraseUser"]
	for _, want := range []string{
		"email = :email, ",
		"erased_at = NOW(), ",
		"WHERE id = :user_id AND erased_at IS NULL RETURNING id AS user_id",
	} {
		if !strings.Contains(erase, want) {
			t.Errorf("EraseUser lacks %q:\n%s", want, erase)
		}
	}
	if !strings.Contains(m["EnableUsers"], "AND erased_at IS NULL") {
		t.Errorf("EnableUsers can re-enable an erased account:\n%s", m["EnableUsers"])
	}
	if !strings.Contains(m["UpdateUser"], "WHERE id = :user_id AND erased_at IS NULL") {
		t.Errorf("UpdateUser can re-personalise an erased account:\n%s", m["UpdateUser"])
	}
	for name, wants := range map[string][]string{
		"EraseOAuthData": {
			// The codes of the sign-in that created the account carry no
			// user_id: found by the identity they carry, while it still does.
			"UPDATE @module.OAuthLoginCode c SET consumed_at = NOW() WHERE c.user_id IS NULL AND c.consumed_at IS NULL AND EXISTS (SELECT i.id FROM @module.OAuthIdentity i WHERE i.user_id = :user_id AND i.provider_id = c.provider_id AND i.external_id = c.external_id)",
			"UPDATE @module.OAuthLoginCode c SET email = \\'\\', external_id = \\'\\' WHERE c.user_id IS NULL AND EXISTS (SELECT i.id FROM @module.OAuthIdentity i WHERE i.user_id = :user_id AND i.provider_id = c.provider_id AND i.external_id = c.external_id)",
			"UPDATE @module.OAuthIdentity SET external_id = id, email = \\'\\' WHERE user_id = :user_id",
			"UPDATE @module.OAuthLoginCode SET consumed_at = NOW() WHERE user_id = :user_id AND consumed_at IS NULL",
		},
		"EraseTwoFactorData": {
			"UPDATE @module.UserTotpSecret SET seed = NULL, secret = NULL, confirmed_at = NULL WHERE user_id = :user_id",
			"UPDATE @module.UserRecoveryCode SET used_at = NOW() WHERE user_id = :user_id AND used_at IS NULL",
			"UPDATE @module.MfaChallenge SET consumed_at = NOW() WHERE user_id = :user_id AND consumed_at IS NULL",
		},
		"SpendEmailVerificationTokens": {"UPDATE @module.EmailVerificationToken SET consumed_at = NOW() WHERE user_id = :user_id AND consumed_at IS NULL"},
		// NULL, never a placeholder (the pending-invite partial index), and a
		// pending invitation ended first: NULL on a live one would make it OPEN.
		"EraseOrgInviteAddress": {
			"UPDATE @module.OrgInvite SET email = NULL, expires_at = NOW() WHERE email = :email AND accepted_at IS NULL AND expires_at > NOW()",
			"UPDATE @module.OrgInvite SET email = NULL WHERE email = :email",
		},
	} {
		body := m[name]
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, body)
			}
		}
		if strings.Contains(body, "DELETE") || strings.Contains(body, "RETURNING") {
			t.Errorf("%s deletes, or fails on an account with nothing to erase (RETURNING):\n%s", name, body)
		}
	}
	// The unlinked codes are matched by the identity's subject, so they must
	// be erased BEFORE the identities' subject is replaced.
	oauth := m["EraseOAuthData"]
	if a, b := strings.Index(oauth, `name: "unlinked_codes"`), strings.Index(oauth, `name: "main"`); a < 0 || b < a {
		t.Errorf("EraseOAuthData rewrites the identities before erasing the codes found through them:\n%s", oauth)
	}
	if erasedAddress("u1") != "erased-u1@erased.invalid" {
		t.Errorf("placeholder = %q", erasedAddress("u1"))
	}
}

// An auth client is revoked, not deleted: the resolvers refuse a revoked
// registration and the enable toggle cannot restore one.
func TestAuthClientStatements(t *testing.T) {
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	m := rpcBodies(dqlText(authProtos(t)["mutations/auth_mutation.proto"]))
	for _, name := range []string{"GetRegisteredRedirect", "GetAuthClientSecret"} {
		if !strings.Contains(q[name], "AND c.revoked_at IS NULL") {
			t.Errorf("%s resolves a revoked registration:\n%s", name, q[name])
		}
	}
	if !strings.Contains(q["ListAuthClients"], "c.revoked_at AS revoked_at") {
		t.Errorf("ListAuthClients does not show which registrations are revoked:\n%s", q["ListAuthClients"])
	}
	if !strings.Contains(m["SetAuthClientEnabled"], "WHERE id = :id AND revoked_at IS NULL") {
		t.Errorf("SetAuthClientEnabled can restore a revoked registration:\n%s", m["SetAuthClientEnabled"])
	}
	if !strings.Contains(m["RevokeAuthClient"], "UPDATE @module.AuthClient SET revoked_at = NOW(), enabled = FALSE WHERE id = :id AND revoked_at IS NULL") {
		t.Errorf("RevokeAuthClient is not a guarded UPDATE:\n%s", m["RevokeAuthClient"])
	}
	// The unique index stays FULL: a partial one is refused on MySQL, and
	// client_id is the operator's choice, so a revoked pair stays taken and
	// RegisterClient says so (TestRegisterClient_ARevokedPairIsRefusedClearly).
	models := authProtos(t)["types/models.proto"]
	i := strings.Index(models, "message AuthClient {")
	block := models[i : i+strings.Index(models[i:], "\n}\n")]
	if !strings.Contains(block, `{ unique: true, fields: [{ name: "client_id" }, { name: "redirect_uri" }] }`) || strings.Contains(block, "where:") {
		t.Errorf("the AuthClient (client_id, redirect_uri) unique index is not the full one:\n%s", block)
	}
}

// The admin pages offer no delete for users and sessions: the Users and
// ServiceAccounts pages erase, the Sessions page revokes — through the service
// methods that record the operator.
func TestAdminPagesEraseAndRevokeNeverDelete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	for _, banned := range []string{"AuthMutation.DeleteUser", "delete: AuthMutation.RevokeUserToken", "update: AuthMutation.UpdateUser"} {
		if strings.Contains(manifest, banned) {
			t.Errorf("plugin.yaml still binds %s", banned)
		}
	}
	for _, page := range []string{"name: Users\n", "name: ServiceAccounts\n", "name: Sessions\n"} {
		i := strings.Index(manifest, page)
		if i < 0 {
			t.Fatalf("no %q page", strings.TrimSpace(page))
		}
		block := manifest[i:]
		if end := strings.Index(block[1:], "\n      - name: "); end > 0 {
			block = block[:end+1]
		}
		if strings.Contains(block, "delete:") {
			t.Errorf("page %s still has a delete:\n%s", strings.TrimSpace(page), block)
		}
		want := "source: AuthService.EraseUsers"
		if page == "name: Sessions\n" {
			want = "source: AuthService.RevokeSessions"
		}
		if !strings.Contains(block, want) {
			t.Errorf("page %s lacks the %s action:\n%s", strings.TrimSpace(page), want, block)
		}
	}
}

// ── the auth client, revoked by the handler ─────────────────────────────────

type clientRow struct {
	id, clientID, redirect string
	enabled                bool
	revokedAt              *timestamppb.Timestamp
}

// clientRegistry is the AuthClient table as its statements keep it.
type clientRegistry struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	rows map[string]*clientRow
}

func (c *clientRegistry) GetRegisteredRedirect(_ context.Context, in *pb.GetRegisteredRedirectReq, _ ...grpc.CallOption) (*pb.GetRegisteredRedirectResp, error) {
	for _, r := range c.rows {
		if r.clientID == in.GetClientId() && r.redirect == in.GetRedirectUri() && r.enabled && r.revokedAt == nil {
			return &pb.GetRegisteredRedirectResp{Client: &pb.AuthClient{Id: r.id, ClientId: r.clientID, RedirectUri: r.redirect, Enabled: true}}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

func (c *clientRegistry) RevokeAuthClient(_ context.Context, in *pb.RevokeAuthClientReq, _ ...grpc.CallOption) (*pb.RevokeAuthClientResp, error) {
	r := c.rows[in.GetId()]
	if r == nil || r.revokedAt != nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.revokedAt, r.enabled = timestamppb.Now(), false
	return &pb.RevokeAuthClientResp{Id: r.id}, nil
}

func (c *clientRegistry) SetAuthClientEnabled(_ context.Context, in *pb.SetAuthClientEnabledReq, _ ...grpc.CallOption) (*pb.SetAuthClientEnabledResp, error) {
	r := c.rows[in.GetId()]
	if r == nil || r.revokedAt != nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.enabled = in.GetEnabled()
	return &pb.SetAuthClientEnabledResp{Id: r.id}, nil
}

// DeleteClient keeps the registration as a revoked row; the redirect is then
// refused exactly as an unregistered one, enabling it again is refused, and a
// second revoke is done, not an error.
func TestRevokeClient_KeepsTheRowAndRefusesItLikeAnUnregisteredOne(t *testing.T) {
	const redirect = "https://app.example.com/cb"
	c := &clientRegistry{rows: map[string]*clientRow{
		"c1": {id: "c1", clientID: "app", redirect: redirect, enabled: true},
	}}
	h := &AuthServiceHandler{Query: c, Mutation: c}
	ctx := sessionCallerCtx("admin", "t-admin")
	if err := h.checkRedirectAllowed(ctx, "app", redirect); err != nil {
		t.Fatalf("the live registration was refused: %v", err)
	}
	if _, err := h.DeleteClient(ctx, &pb.DeleteClientReq{Id: "c1"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	row := c.rows["c1"]
	if row == nil || row.revokedAt == nil {
		t.Fatalf("the registration is gone or not revoked: %+v", row)
	}
	revoked := h.checkRedirectAllowed(ctx, "app", redirect)
	unregistered := h.checkRedirectAllowed(ctx, "app", "https://never.example.com/cb")
	if revoked == nil || revoked.Error() != unregistered.Error() {
		t.Errorf("a revoked registration answers %v, an unregistered one %v — they must be the same", revoked, unregistered)
	}
	if _, err := h.SetClientEnabled(ctx, &pb.SetClientEnabledReq{Id: "c1", Enabled: true}); status.Code(err) != codes.NotFound {
		t.Errorf("enabling a revoked registration answered %v, want NotFound", err)
	}
	if row.enabled {
		t.Error("a revoked registration was enabled again")
	}
	if _, err := h.DeleteClient(ctx, &pb.DeleteClientReq{Id: "c1"}); err != nil {
		t.Errorf("a second revoke failed: %v", err)
	}
}
