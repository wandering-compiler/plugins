// Package handlers contains the auth plugin's authored Go
// business handlers — canonical implementations of
// AuthService.Authenticate / SignIn / SignUp.
//
// Each method is deliberately anti-enumeration: every failure
// path returns the SAME opaque codes.Unauthenticated status
// with the same message so callers can't distinguish
// "no-such-token" from "malformed header" from "wrong password"
// from "transient DB error".
//
// Dependencies (Query, Mutation typed-client interfaces) are
// populated by the plugin's RegisterPlugin function before
// Init() runs. Plugin author tests construct
// *AuthServiceHandler directly, inject mock pb.AuthQueryClient /
// pb.AuthMutationClient, and exercise the methods with standard
// Go testing — no codegen, no staging.
package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/auth/lib/passwordhash"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
)

// randomURLToken returns a fresh 256-bit URL-safe random token — the
// plaintext password-reset / email-verification token handed to the
// user once (via the emitted event). Lives here (always-compiled) so both
// feature-gated handler files can share it without a cross-file dependency.
func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceMinVerifierLen is RFC 7636 §4.1's minimum code_verifier length (the
// floor of the 43–128 unreserved-charset range). A too-short verifier
// weakens the challenge; we enforce the floor (not the exact charset — the
// hash comparison already rejects a tampered verifier).
const pkceMinVerifierLen = 43

// s256Challenge is BASE64URL(SHA256(verifier)), the PKCE S256 challenge.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyPKCES256 reports whether s256Challenge(verifier) equals the stored
// challenge, compared in constant time.
func verifyPKCES256(verifier, challenge string) bool {
	return hmac.Equal([]byte(s256Challenge(verifier)), []byte(challenge))
}

// sha256Hex is the one-way function applied to a reset / verification token for
// storage + lookup — only the hash is persisted, so a DB read can't redeem a
// token.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// defaultSessionTokenTTLSeconds is the fallback session bearer lifetime
// (30 days) when session_token_ttl_seconds is unset / <= 0.
const defaultSessionTokenTTLSeconds = 30 * 24 * 60 * 60

// scopeUserIDKey / userMetadataKey are the gRPC metadata keys the
// gateway threads the authenticated principal under: the
// AuthResp.scopes["user_id"] entry, and the always-present
// base64(marshaled AuthResp) envelope.
//
// Handler code reads them through principal.UserID / principal.Envelope
// rather than by hand — these consts exist for the tests, which build
// the metadata a gateway would stamp. principal owns the wire contract
// (it is dependency-light public sdk/go, so using it keeps this module
// free of any srcgo dependency).
const (
	scopeUserIDKey  = "x-w17-scope-user_id"
	userMetadataKey = "x-w17-user"
)

// Authn-flow gate sentinels — cause values handler passes to
// Unauthenticated when failure is shape-level (not an
// underlying error). They never reach the wire; the SDK auditor
// walks errors.Unwrap to verify all failure paths
// converge on Unauthenticated.
var (
	errAuthnHeaderMissing    = errors.New("auth header missing")
	errAuthnSchemeMismatch   = errors.New("auth scheme prefix mismatch")
	errAuthnTokenEmpty       = errors.New("auth token empty after scheme strip")
	errAuthnPasswordMismatch = errors.New("password verify failed")
	errAuthnNoPrincipal      = errors.New("no authenticated principal in scope metadata")
)

// AuthServiceHandler implements every method of the plugin's
// AuthService. Every field is set by the caller (the plugin's
// RegisterPlugin) at construction — no Init / two-phase setup.
// Fields divide into typed-client dependencies (Query, Mutation),
// configurable knobs (HeaderName, Scheme, PasswordHash), and
// author-defined state (none today; rate limiters / per-IP
// buckets / nonce caches land here when needed).
//
// No `Logger` field — observability is handled by the bundle's
// stack (Sentry via observx, OTel via otelgrpc's stats handler
// + ChainUnaryInterceptor). Per-RPC errors land on the span
// automatically; handler-local logging would bypass that
// routing and produce stderr-only output the operator can't
// reach through their existing observability tooling.
//
// Storage returns permission IDs already typed as int32 and the
// plugin passes them through into AuthResp.permission_ids verbatim;
// the gateway resolves the bit checks against the slice at the
// per-handler call site. The ONE exception is a wildcard
// (`all_permissions`) role: the AclPermission catalogue is a
// compile-time proto enum (no DB table), so storage can't
// enumerate it in SQL. Storage instead returns an `all_permissions`
// bool alongside the IDs, and Authenticate expands the grant to
// acllock.GrantAll(Lock) — the compile-time lock reached via
// RegisterPlugin (clients.AclLock()).
type AuthServiceHandler struct {
	Query    pb.AuthQueryClient
	Mutation pb.AuthMutationClient

	// DistTx + Connection wire the in-process distributed-transaction
	// coordinator (bundle's shared txregistry) so multi-mutation handlers —
	// SignUp composes CreateUser + role assignment + IssueToken — run in ONE
	// transaction: distx.Begin(Connection) → thread w17-tx-id → Commit/Rollback.
	// Both set by RegisterPlugin from the ClientSet; nil/"" in a hand-built
	// test handler that doesn't exercise the transactional path (SignUp then
	// falls back to non-atomic sequential calls — fine for a unit test).
	DistTx     distxpb.W17DistributedTransactionClient
	Connection string

	// Lock is the bundle's compile-time ACL permission-lock snapshot
	// (query.AclLock(), wired by RegisterPlugin). Non-nil in a wired
	// bundle; nil only in a hand-built test handler that never
	// exercises the wildcard path. Read solely to expand an
	// `all_permissions` wildcard role via acllock.GrantAll.
	Lock *acllock.Lock

	PasswordHash passwordhash.Settings

	HeaderName string
	Scheme     string

	// two_factor knobs (set from env in RegisterPlugin; ignored when the
	// feature is off — only handlers/mfa.go reads them). Plain types so
	// this always-compiled file stays free of the totp / secretbox
	// imports; mfa.go builds the secretbox cipher from TwoFactorSecretKey.
	TwoFactorTOTP     bool   // built-in TOTP verify path enabled (two_factor_totp)
	TwoFactorScope    string // all_logins | new_devices (two_factor_scope)
	MfaCodeTTLSeconds int    // event-flow challenge code lifetime (mfa_code_ttl_seconds)
	// Issuance cap: at most MaxMfaChallengesPerWindow challenges
	// per user per MfaChallengeWindowSeconds. The per-challenge attempt
	// budget bounds guesses against one challenge; this bounds how many
	// challenges — and so how many budgets — a caller can buy. <= 0 → the
	// defaults in mfa.go.
	MaxMfaChallengesPerWindow int // mfa_max_challenges_per_window
	MfaChallengeWindowSeconds int // mfa_challenge_window_seconds

	// SessionTokenTTLSeconds is the absolute lifetime stamped into a
	// freshly minted session bearer token's expires_at (from
	// session_token_ttl_seconds). <= 0 → defaultSessionTokenTTLSeconds.
	SessionTokenTTLSeconds int
	TotpIssuer             string // otpauth:// issuer label (totp_issuer); empty → project/domain name
	TwoFactorSecretKey     string // base64 32-byte key encrypting TOTP seeds at rest (two_factor_secret_key)

	// oauth knob (set from env in RegisterPlugin; read only by
	// handlers/oauth.go). Public base URL the callback is reachable at;
	// empty → derived from the request Host.
	OAuthRedirectBase string // oauth_redirect_base

	// Reset / verification token lifetimes (set from env in RegisterPlugin;
	// read only by handlers/reset.go / emailverify.go). <= 0 → the file's
	// default.
	PasswordResetTTLSeconds     int // password_reset_ttl_seconds
	EmailVerificationTTLSeconds int // email_verification_ttl_seconds

	InviteOnly bool // require a pending org invitation to sign up (invite_only)
	// EmailProofRequired is the FLOOR an address must reach before
	// AcceptOrgInvite will admit it: "none", "derived" or "full"
	// (email_proof_required).
	//
	// It replaced a boolean, and the reason is the middle value: a bound
	// invitation names the address and the secret link reached whoever
	// registered, which is a real proof and a weaker one than a confirmation
	// the person completed themselves. A boolean could say "verified or not"
	// and could not say "this much" — so a deployment that wanted the
	// address-guessing hole closed had to demand a round trip nobody needed.
	//
	// Defaults to "none" and deliberately not to something stricter: every
	// account that exists today is UNPROVEN, so a stricter default would
	// refuse invitations those people were legitimately sent. Turning it up is
	// the deployment's call, and saying that plainly beats a default that reads
	// as safe and is really a breaking change — which is the same reasoning the
	// boolean carried, kept because it did not stop being true.
	EmailProofRequired string
	OrgInviteTTLHours  int // how long an invitation stays acceptable (org_invite_ttl_hours)

	// APITokenDefaultTTLHours is the lifetime of an API token minted without
	// an explicit expires_at (api_token_default_ttl_hours). 0 = never expires;
	// negative falls back to the 90-day default. See apiTokenExpiry.
	APITokenDefaultTTLHours int

	// SignUpAllowlist is who may register at all (sign_up_allowlist): addresses
	// and @domains, comma- or space-separated; empty = everyone. Read through
	// parseSignUpAllowlist at every gate rather than parsed once into hidden
	// state, so a handler built without ValidateConfig enforces the same list.
	SignUpAllowlist string

	// sign_up_confirmation_ttl_seconds (read only by handlers/signup_confirm.go).
	// <= 0 → the file's default.
	SignUpConfirmationTTLSeconds int
}

// scopeDecorator augments the AuthResp scope + label maps for an
// authenticated principal. Feature-gated handler files register
// decorators via init(); Authenticate runs them after stamping the
// canonical user_id scope, so each opt-in feature can publish its
// own scope (e.g. tenant_scope → scopes["tenant_id"]) without the
// base handler knowing about it. Declared here (always-present) so
// Authenticate compiles with zero feature files staged — an empty
// slice is a no-op. A decorator returning an error fails
// Authenticate closed (the same opaque Unauthenticated path).
//
// `labels` is the BROADCAST audience key and is passed separately
// BECAUSE it is not the same set as scopes — see AuthResp.labels in
// the proto. A decorator writes a label only for a key that genuinely
// partitions who may SEE an event; most write none, and an empty map
// leaves today's every-client broadcast untouched.
// `headers` is the AuthReq header map — the SAME channel the bearer token
// arrives on, and the only one every transport fills. It is passed
// explicitly because reading a client-sent selector off the gRPC context
// instead does not work on a public gRPC surface: the rpc gateway builds
// the sanitized metadata, hands it over as AuthReq.Headers, and then calls
// Authenticate with the raw incoming context — which carries no OUTGOING
// metadata, and `grpcclient.Dial` installs no forwarding interceptor. REST
// only worked because its MetadataPropagation middleware stamps outgoing
// metadata before the handler runs. Two channels for two values that
// arrive together is what hid it.
type scopeDecorator func(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error

var scopeDecorators []scopeDecorator

// grantNarrower rewrites the principal's permission set AFTER the scope
// decorators have run, so a feature that resolves a request-scoped
// context can restrict the grants to it. `org_membership` registers one:
// the unfiltered set is the union of every role the user holds in every
// organization, and serving that inside one org is exactly the
// cross-tenant leak the feature exists to close.
//
// APPENDED, never assigned — that is the whole point of it being a
// separate seam. `resolvePrincipal` is a single var that the realm axis
// owns (`api_token` replaces it wholesale), so a second feature
// assigning it too would win or lose by init order — filename order,
// silently, with the loser's behaviour simply gone. A narrower composes
// instead of competing.
//
// Contract: a narrower may only REMOVE permissions or expand a wildcard
// it has itself re-checked in the narrower context. Returning a larger
// ordinary set would let a feature escalate the principal past the realm
// resolution that ran before it.
type grantNarrower func(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, scopes map[string]string) error

var grantNarrowers []grantNarrower

// principal is what a validated token resolves to, before any narrowing.
//
// Grants are carried ROLE-ATTRIBUTED rather than as a flat permission set,
// and that is the whole point: two narrowing axes (realm, organization)
// intersect on roles, so a permission survives only when a SINGLE role grants
// it and that role passes both. A flat set cannot express that — it forgets
// which role contributed what, and an intersection then keeps permissions that
// no one role grants under both axes.
//
// Realm rides along because one narrowing needs it: organization OWNERSHIP
// widens, and it may only widen a SESSION principal (see narrowGrantsToActiveOrg).
type authPrincipal struct {
	userID  string
	tokenID string
	realm   pb.TokenType
	grants  []*pb.RoleGrant

	// usedTokenID / lastUsedAt are the row the bearer resolved to, whatever
	// its kind (tokenID is a session's only), and when it was last recorded
	// as used — read by recordTokenUse once authentication succeeded.
	usedTokenID string
	lastUsedAt  *timestamppb.Timestamp

	// deviceThumbprint / deviceRevokedAt are the device the token is bound
	// to (empty: bound to none) and when it was revoked (nil: live), read by
	// the token lookup itself so the binding check costs no round trip.
	deviceThumbprint string
	deviceRevokedAt  *timestamppb.Timestamp

	// mcpOnly is UserToken.mcp_only: a token of the MCP OAuth flow, accepted
	// without a proof on the MCP surface and nowhere else.
	mcpOnly bool

	// legacyToken is the presented token when it resolved to a LEGACY row
	// (stored in the clear, no hash yet), "" otherwise. The resolvers only
	// note it; Authenticate moves the row to the hash once the request has
	// passed every check, so a refused request writes nothing.
	legacyToken string
}

// legacyPlaintext is the token to move to the hash: the presented one when the
// row it resolved to has no stored hash (a legacy row), "" otherwise.
func legacyPlaintext(token, storedHash string) string {
	if storedHash != "" {
		return ""
	}
	return token
}

// recordTokenUse stamps the accepted token's last_used_at. Base no-op: the
// column exists only under `api_token`, whose file (handlers/apitoken.go)
// installs the real one via init(). Called once authentication has
// succeeded, so a refused request records nothing. Must never fail the
// request it rides on.
var recordTokenUse = func(ctx context.Context, h *AuthServiceHandler, p *authPrincipal) {}

// effectivePermissions flattens the surviving grants into the permission set
// Authenticate answers with. A wildcard grant that survived every axis expands
// from the DEPLOYED LOCK, never from RolePermission rows — a wildcard role
// stores none, so reading the table would silently drop exactly the
// permissions only that role carries.
func (p *authPrincipal) effectivePermissions(lock *acllock.Lock) []int32 {
	seen := map[int32]struct{}{}
	var out []int32
	add := func(ids []int32) {
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	for _, g := range p.grants {
		if g.GetAllPermissions() {
			add(acllock.GrantAll(lock))
			continue
		}
		add(g.GetPermissionIds())
	}
	return out
}

// resolvePrincipal turns a validated token string into the
// authenticated principal's id + the permission IDs it carries. The
// default is the single-realm session path: one round-trip through
// GetUserByTokenWithPermissions, every role counted. The api_token
// feature file (handlers/apitoken.go) overrides this via init() with
// the realm-aware path — branch on token_type, count only the matching
// realm's roles, and intersect an API token with its permission subset.
// Declared here (always-present) so Authenticate compiles with no
// feature file staged; the override only ships when api_token is on.
var resolvePrincipal = resolvePrincipalSession

// resolvePrincipalSession is the default resolvePrincipal, named so a test
// reaches it even in a build where api_token's init() replaced the variable.
func resolvePrincipalSession(ctx context.Context, h *AuthServiceHandler, token string) (*authPrincipal, error) {
	hash := sha256Hex(token)
	resp, err := h.Query.GetUserByTokenWithPermissions(ctx, &pb.GetUserByTokenWithPermissionsReq{LegacyToken: token, TokenHash: hash})
	if err != nil {
		// With api_token off every token is a session.
		return nil, expiredTokenRefusal(err, func() (endedToken, error) {
			exp, err := h.Query.GetExpiredToken(ctx, &pb.GetExpiredTokenReq{LegacyToken: token, TokenHash: hash})
			return endedToken{
				expiresAt:       exp.GetExpiresAt(),
				revokedAt:       exp.GetRevokedAt(),
				kind:            pb.TokenType_TOKEN_TYPE_SESSION,
				thumbprint:      exp.GetDeviceThumbprint(),
				deviceRevokedAt: exp.GetDeviceRevokedAt(),
			}, err
		})
	}
	// A disabled account's tokens are revoked when it is disabled, but one
	// minted after that (a sign-in racing the disable) must not work either.
	if err := signInDisabledGate(resp.GetUser()); err != nil {
		return nil, err
	}
	// SESSION: with api_token off there is only one credential class, and
	// this is it. Stamping it rather than leaving the zero value keeps the
	// ownership rule (session-only) reading the same in both builds.
	userID := resp.GetUser().GetId()
	grants, err := h.Query.GetUserRoleGrants(ctx, &pb.GetUserRoleGrantsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &authPrincipal{
		userID:           userID,
		tokenID:          resp.GetTokenId(),
		realm:            pb.TokenType_TOKEN_TYPE_SESSION,
		grants:           grants.GetGrants(),
		deviceThumbprint: resp.GetDeviceThumbprint(),
		deviceRevokedAt:  resp.GetDeviceRevokedAt(),
		mcpOnly:          resp.GetMcpOnly(),
		legacyToken:      legacyPlaintext(token, resp.GetStoredTokenHash()),
	}, nil
}

// signupResolveRoleIDs + signupAssignRoleIDs are the two halves of turnkey
// declarative role assignment, split so SignUp can RESOLVE the role set from
// COMMITTED state (reads run on the pool — query servers don't join the distx
// tx) BEFORE opening its write transaction, then ASSIGN inside it. Doing the
// count-based first-user decision inside the tx would misread (the new user is
// still uncommitted and invisible to the pooled read), so the decision must
// happen up front. Both default to no-ops — the base build has no RBAC tables;
// the `rbac` feature file (handlers/signup_roles.go) overrides them via init().
// Declared here (always-compiled) so SignUp compiles whether or not rbac is
// staged; the overrides only ship when rbac is on.
var signupResolveRoleIDs = func(ctx context.Context, h *AuthServiceHandler) (signupRoles, error) {
	return signupRoles{}, nil
}
var signupAssignRoleIDs = func(ctx context.Context, h *AuthServiceHandler, userID string, roles signupRoles) error {
	return nil
}

// signupRoles is what the resolve half hands the assign half. `bootstrap`
// marks the first_user set: the assign half must then win the bootstrap
// claim inside the transaction, and assigns `fallback` (the default roles)
// if another sign-up holds it.
type signupRoles struct {
	ids       []string
	bootstrap bool
	fallback  []string
}

// spendResetLinks marks every live password-reset link of an account used.
// A reset and a password change both call it inside their transaction: after
// the password changed, an older link is a way to change it again. Base
// no-op — the PasswordResetToken table exists only under `password_reset`,
// whose file (handlers/reset.go) installs the real one via init(), so
// `password_change` without `password_reset` stages nothing it cannot build.
var spendResetLinks = func(ctx context.Context, h *AuthServiceHandler, userID string) error { return nil }

// eraser erases one feature's share of an account's personal data, inside the
// erasure's transaction (AuthService.EraseUsers, `user_admin`): email is the
// address being erased (as stored), placeholder the one replacing it. Nothing
// it runs deletes a row.
type eraser func(ctx context.Context, h *AuthServiceHandler, userID, email, placeholder string) error

// erasers are the feature-owned halves of an erasure. Each feature whose
// tables hold personal data (oauth, two_factor, email_verification,
// org_invite) appends its own from its file's init(), so the list holds
// exactly the tables this activation has; password_reset's share is
// spendResetLinks above. Declared here, always compiled, because the features
// that append and the one that runs them (user_admin) stage independently.
var erasers []eraser

// SignIn seams — always-present default behaviours opt-in feature
// files override via init(), mirroring resolvePrincipal /
// signupCreateUser / scopeDecorators. They let `two_factor` (and the
// account gates) layer into the password sign-in without the base
// handler knowing about them. With no feature file staged the
// defaults make SignIn the plain GetUserByEmail → verify → register the
// device → IssueToken flow.

// defaultAPITokenTTLHours is the lifetime of an API token whose caller asked
// for none, when the deployment did not choose one: 90 days.
//
// Both live in this always-staged file, not beside apiTokenExpiry
// (apitoken.go, staged with api_token): ValidateConfig runs in every
// activation, and a constant only api_token stages would leave every
// activation without it unable to build.
const defaultAPITokenTTLHours = 90 * 24

// maxAPITokenTTLHours bounds the default lifetime (100 years). A longer one is
// refused at boot by ValidateConfig: time.Duration overflows past ~292 years,
// and "never" is spelled 0.
const maxAPITokenTTLHours = 100 * 365 * 24

// ValidateConfig fails plugin bootstrap loud on a contradictory
// activation, rather than silently degrading. Called from RegisterPlugin
// after the handler is built. (two_factor_scope=new_devices no longer needs
// the `devices` feature: device identity is base tier, so every activation
// knows which device signs in.)
func ValidateConfig(h *AuthServiceHandler) error {
	// Refused at boot rather than at the first mint: past this many hours
	// time.Duration overflows, and a "practically never" setting would mint
	// tokens already expired — accepted by the mint, refused by every read.
	if h.APITokenDefaultTTLHours > maxAPITokenTTLHours {
		return fmt.Errorf("auth plugin: api_token_default_ttl_hours=%d is longer than %d (100 years) — use 0 for tokens that never expire", h.APITokenDefaultTTLHours, maxAPITokenTTLHours)
	}
	// At boot, because the failure is silent otherwise: an entry that matches
	// no address keeps out exactly the people it was written for.
	if _, err := parseSignUpAllowlist(h.SignUpAllowlist); err != nil {
		return err
	}
	return nil
}

// parseSignUpAllowlist reads sign_up_allowlist: addresses (`ceo@example.com`)
// and whole domains (`@example.com`), separated by commas or whitespace,
// lower-cased. Anything else is an error naming the entry.
func parseSignUpAllowlist(raw string) ([]string, error) {
	var out []string
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		e := strings.ToLower(strings.TrimSpace(entry))
		at := strings.LastIndex(e, "@")
		domain := e[at+1:]
		if at < 0 || domain == "" || !strings.Contains(domain, ".") || strings.Count(e, "@") != 1 {
			return nil, fmt.Errorf("auth plugin: sign_up_allowlist entry %q is neither an address (name@example.com) nor a domain (@example.com)", entry)
		}
		out = append(out, e)
	}
	return out, nil
}

// errSignUpClosed is the refusal for an address outside sign_up_allowlist.
// The same answer whatever else is true of the address — an account, an
// invitation — so the form cannot be used to read the list.
var errSignUpClosed = withUserDetail(status.New(codes.PermissionDenied,
	"registration is not open for this address"), CodeSignUpClosed, MsgSignUpClosed).Err()

// signUpAllowlistGate refuses an address sign_up_allowlist does not name. It
// is called by every door that creates an account for whoever is knocking —
// SignUp, ConfirmSignUp and the OAuth sign-up — and not by the administrator's
// paths, which create accounts on purpose. A malformed list refuses everyone
// rather than no one: ValidateConfig already failed the boot for it, so this
// is reached only by a handler built around that check.
func signUpAllowlistGate(h *AuthServiceHandler, email string) error {
	allow, err := parseSignUpAllowlist(h.SignUpAllowlist)
	if err != nil {
		return errSignUpClosed
	}
	if len(allow) == 0 {
		return nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	for _, a := range allow {
		if a == email || (strings.HasPrefix(a, "@") && at >= 0 && email[at:] == a) {
			return nil
		}
	}
	return errSignUpClosed
}

// markEmailConfirmed records that the person proved the address themselves —
// a sign_up_confirmation code came back from it. A seam for markEmailDerived's
// reason: the columns it writes exist only with `email_verification`, and
// without that feature there is nothing to record and nothing to refuse.
var markEmailConfirmed = func(_ context.Context, _ *AuthServiceHandler, _ string) error {
	return nil
}

// inviteVerifiedEmailGate refuses an acceptance from an account whose address
// was never proved to belong to it.
//
// A no-op by default, and replaced by the real check when `email_verification`
// is staged — the pattern the device and disabled-account gates use, and
// required rather than stylistic: `User.email_verified_at` exists only when
// that feature is on, so naming the field from an always-staged file would
// fail the BUNDLE build of every project that runs org_invite without it.
//
// ⚠️ IT LIVES HERE, in an always-staged file, and not beside its caller in
// `org_invite.go`. Two features stage independently, so the seam has to exist
// for every combination of them:
//
//	org_invite on,  email_verification off — caller present, no implementation
//	org_invite off, email_verification on  — implementation present, no caller
//
// The second one is the trap. `emailverify.go` assigns this var in its init,
// so declaring it in the gated `org_invite.go` meant an activation with
// verification and no invitations staged the assignment without the
// declaration and failed the bundle build on an undefined identifier —
// breaking a combination that has nothing to do with invitations.
//
// The fix is not to make `email_verification` require `org_invite`: that would
// force invitations on every project that only wants to confirm addresses.
// A seam spans the features it joins, so it belongs above both.
//
// # Why this exists at all
//
// An invitation is keyed on an ADDRESS and accepted by whoever holds an
// account with it, so the proof is "I own this mailbox" — and until now
// nothing checked that the account's address had ever been proved. Both the
// OrgInvite model and the invite_only knob said that window "closes when
// email_verification is enabled". It did not: the feature adds a column and
// two RPCs and blocks nothing, so a project could enable it, verify nobody,
// and still be told by its own documentation that it was covered.
//
// The answer is: this, and only if asked. See `email_proof_required` in
// plugin.yaml for why it is opt-in rather than automatic.
//
// The last argument says whether the invitation being accepted BINDS an address.
// It is here rather than derived inside, because only the caller holds the
// invitation at that moment and the gate must run before the row is spent: a
// bound invitation derives the address by being accepted, an open one derives
// nothing, and the difference is what the middle floor is for.
var inviteVerifiedEmailGate = func(_ context.Context, _ *AuthServiceHandler, _ string, _ bool) error {
	return nil
}

// markEmailDerived records that a BOUND invitation proved the caller's address.
//
// A seam for the same reason the gate above is one: `User.email_proof` is
// field-gated on `email_verification`, so the column — and the mutation that
// writes it — exist only when that feature is staged. A no-op here means the
// project declined the feature, not that the derivation failed, and an
// invitation must keep working either way.
var markEmailDerived = func(_ context.Context, _ *AuthServiceHandler, _ string) error {
	return nil
}

// errSignUpNotInvited is the refusal under `invite_only`. It names the
// remedy — ask for an invitation — because the person reading it did
// nothing wrong and has no other way to learn that registration is closed:
// the form accepted their input and the server said no.
//
// It deliberately does NOT say whether the address has an invitation that
// merely expired, nor whether an account already exists. Either would turn
// the registration form into a probe for who has been invited where.
// A gRPC STATUS, not a bare error: the gateway maps an unclassified error
// to INTERNAL, so a plain errors.New would reach the browser as a 500
// saying "internal error" — the caller would see a server fault instead of
// the sentence that tells them what to do. Measured, not assumed: the
// first version of this was a bare error and answered HTTP 500.
var errSignUpNotInvited = withUserDetail(status.New(codes.PermissionDenied,
	"registration is by invitation only — ask an administrator of the organization you are joining to invite this address"),
	CodeSignUpNotInvited, MsgSignUpNotInvited).Err()

// errInviteOtherAddress refuses a registration whose invitation link is bound
// to another address, when nothing else invites this one. It does not say
// which address the invitation names.
var errInviteOtherAddress = withUserDetail(status.New(codes.PermissionDenied,
	"the invitation link is bound to a different address than the one registering"),
	CodeInviteOtherAddress, MsgInviteOtherAddress).Err()

// signupInviteGate decides whether an address may create an account at all.
//
// Permissive by default: with no `org_invite` staged there are no
// invitations to require, and a gate that refused everything would be the
// wrong default for every activation that has never heard of them.
// handlers/org_invite.go's init() installs the enforcing one.
//
// It lives HERE, in the always-compiled file, and not beside SignUp, for
// two reasons that were both learned the expensive way:
//
//   - `org_invite` does not require `sign_up_turnkey`. Staged under
//     sign_up_turnkey the seam would vanish from an activation that has
//     invitations and no turnkey registration, and the installing init()
//     would not compile.
//   - SignUp is not the only door. OAuth's createOAuthAccount
//     creates an account for any address the provider asserts, so a gate
//     reachable only from SignUp leaves invite-only registration open to
//     anyone with an account at the identity provider.
//
// The enforcing implementation reads h.InviteOnly at CALL time rather than
// deciding at install time: staging the feature must not close a surface
// the operator left open.
//
// ⚠️ Without an init() installing the enforcing implementation, nothing
// FAILS: the permissive default is a valid state, so every test, every
// build and every deployment stays green while `invite_only` — true by
// default — is read by nobody. The only artefact is an unused variable
// (staticcheck's U1000 on errSignUpNotInvited), which is why the lint has
// to cover this directory.
var signupInviteGate = func(ctx context.Context, h *AuthServiceHandler, email, inviteToken string) error {
	return nil
}

// signupClaimInvite spends an OPEN invitation's link on the registration
// that came through it (see handlers/org_invite.go). Default (no
// `org_invite`): nothing to claim. Called inside the registration's unit of
// work where there is one, so a registration that fails leaves the link
// open.
var signupClaimInvite = func(ctx context.Context, h *AuthServiceHandler, email, inviteToken string) error {
	return nil
}

// signInMfaGate decides whether a second factor challenges this
// sign-in. thumbprint is the device key that signed it: a challenge records
// it, and only that key may complete the sign-in (VerifyMfa). Default (no `two_factor`): never — returns (nil, false,
// nil) so SignIn proceeds straight to token issuance.
// handlers/mfa.go overrides via init(): on a challenge it creates the
// MfaChallenge (emitting MfaChallengeRequested) and returns the
// mfa_required SignInResp + challenged=true so SignIn returns it
// WITHOUT issuing a token.
var signInMfaGate = func(ctx context.Context, h *AuthServiceHandler, user *pb.User, thumbprint string, deviceTrusted bool) (resp *pb.SignInResp, challenged bool, err error) {
	return nil, false, nil
}

// sessionTokenExpiry returns the absolute expiry stamped into a freshly
// minted session bearer token: NOW + session_token_ttl_seconds (default
// 30d when unset/<=0). The token-validation queries reject a token past
// this instant, so a leaked session token stops working after the TTL
// even without an explicit logout. Read by issueSession, SignUp and
// ConfirmSignUp; a CLI session takes the earlier of it and its approver's.
func (h *AuthServiceHandler) sessionTokenExpiry() *timestamppb.Timestamp {
	ttl := h.SessionTokenTTLSeconds
	if ttl <= 0 {
		ttl = defaultSessionTokenTTLSeconds
	}
	return timestamppb.New(time.Now().Add(time.Duration(ttl) * time.Second))
}

// Shutdown runs once on bundle teardown with the bundle's drain
// ctx. No-op today — handler holds no per-instance state worth
// flushing.
func (h *AuthServiceHandler) Shutdown(ctx context.Context) error {
	return nil
}

// Authenticate is the gateway-facing turnkey. The gateway
// parser's validateAuthRequestShape contract guarantees
// req.Headers is non-nil (the parser refuses any AuthService
// activation whose AuthReq lacks the `map<string,string>
// headers` field). The handler:
//
//  1. Pulls the configured auth header off the map (case-folded
//     to lower per the gateway convention).
//  2. Strips the scheme prefix when configured.
//  3. Delegates to AuthQuery.GetUserByTokenWithPermissions —
//     one round-trip resolves identity + permission IDs (int32
//     enum values from the activating domain's AclPermission).
//  4. Runs the scope decorators, then the grant narrowers —
//     the request-scoped context (e.g. the active organization)
//     exists only after step 3, so restricting the permissions
//     to it is a separate pass rather than part of the lookup.
//  5. Passes the surviving IDs through into
//     AuthResp.permission_ids verbatim — no packing, no string
//     lookup. Gateway emits
//     `acllock.HasPermission(ids, int32(pb.AclPermission_X))`
//     per handler against this slice.
//
// Every failure mode returns the same Unauthenticated status.
func (h *AuthServiceHandler) Authenticate(ctx context.Context, req *pb.AuthReq) (*pb.AuthResp, error) {
	return h.authenticate(ctx, req)
}

// AuthenticateAdmin is Authenticate for the admin plane, which the admin
// preset wires as its user_lookup.
//
// The admin is one console across every organization, so only a REALM-wide
// role may count there. Authenticate selects an organization (from
// the request, or the caller's only one) and lets that organization's roles
// grant permissions — right for an app endpoint that works inside the
// organization, and wrong for the admin: a role scoped to one organization,
// a wildcard one above all, would pass every admin page for every
// organization. Here no organization is selected, so the grants that survive
// are the realm-wide ones, and organization ownership grants nothing.
//
// Two consequences a project sees:
//
//   - no org_id scope reaches the admin's storage calls, so an admin page over
//     a model scoped by name: "org_id" is refused ("missing required scope:
//     org_id") for every caller. Before, it served the one organization the
//     sole-org inference happened to pick, which was never the whole console.
//   - the other decorators still run. Under tenant_scope the caller's tenant_id
//     is still stamped, so the admin stays inside the caller's tenant.
//
// The mark is a context value of an unexported type, set only here: nothing a
// caller sends can put a request on the admin plane, and the mark only ever
// removes an organization, never adds one.
func (h *AuthServiceHandler) AuthenticateAdmin(ctx context.Context, req *pb.AuthReq) (*pb.AuthResp, error) {
	return h.authenticate(context.WithValue(ctx, adminPlaneKey{}, true), req)
}

// adminPlaneKey marks a request authenticated for the admin plane; see
// AuthenticateAdmin.
type adminPlaneKey struct{}

func onAdminPlane(ctx context.Context) bool {
	v, _ := ctx.Value(adminPlaneKey{}).(bool)
	return v
}

func (h *AuthServiceHandler) authenticate(ctx context.Context, req *pb.AuthReq) (*pb.AuthResp, error) {
	raw, ok := req.GetHeaders()[strings.ToLower(h.HeaderName)]
	if !ok || raw == "" {
		return nil, Unauthenticated(errAuthnHeaderMissing)
	}
	token, viaDPoP, err := h.presentedToken(raw)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	// Decided BEFORE the token is looked up, so it says nothing about the
	// token: a request that proves no key is refused here, unless the gateway
	// marked it as the MCP surface (whose clients cannot sign yet), where only
	// an MCP-flow token passes — checked after the lookup, with every other
	// outcome the opaque refusal.
	jkt := req.GetHeaders()[dpopJKTKey]
	proofed := viaDPoP && validThumbprint(jkt)
	mcpSurface := req.GetHeaders()[surfaceKey] == surfaceMCP
	if !proofed && !mcpSurface {
		return nil, Unauthenticated(deviceProofRequired(ctx))
	}

	// Resolve identity + permission IDs. Default = single-realm
	// session path; api_token swaps in the realm-aware + subset-
	// narrowed resolver (see resolvePrincipal).
	prin, err := resolvePrincipal(ctx, h, token)
	if err != nil {
		// An expired token says so only to the holder of its key; to anyone
		// else, as an unknown one, it is the opaque refusal.
		if proofed {
			if expired := expiredFor(ctx, err, jkt); expired != nil {
				return nil, Unauthenticated(expired)
			}
		}
		return nil, Unauthenticated(err)
	}
	// The binding, before anything else, so nothing is decorated, narrowed or
	// recorded as used for a request that fails it.
	if proofed {
		err = checkTokenBinding(ctx, prin, jkt)
	} else {
		err = checkMCPToken(prin)
	}
	if err != nil {
		return nil, Unauthenticated(err)
	}
	userID := prin.userID

	// Publish the authenticated principal as the
	// canonical `user_id` data scope. The gateway threads this into
	// `x-w17-scope-user_id` metadata; a consuming project that
	// scopes its owned rows by `name: "user_id"` then gets owner
	// auto-stamp on INSERT + auto-WHERE on SELECT with no hand-
	// written facade.
	scopes := map[string]string{"user_id": userID}

	// Feature-gated scope decorators (e.g. tenant_scope) append
	// their own scopes here. Empty when no feature file is staged.
	labels := map[string]string{}
	if err := runScopeDecorators(ctx, h, userID, req.GetHeaders(), scopes, labels); err != nil {
		return nil, err
	}

	// Grants are narrowed to the request-scoped context the decorators
	// just resolved — org_membership restricts them to the ACTIVE
	// organization. Ordering is the contract: permissions are resolved
	// before the decorators run (one round trip resolves identity +
	// permissions together), so the narrowing has to happen here, after
	// the scope exists. Empty when no feature file is staged, which is
	// why an unscoped build behaves exactly as it did.
	for _, narrow := range grantNarrowers {
		if err := narrow(ctx, h, prin, scopes); err != nil {
			return nil, Unauthenticated(err)
		}
	}

	// Written only now that the request passed every check — the binding
	// included — so a refused request (a stolen token with the wrong key, a
	// narrower's refusal) changes nothing.
	if prin.legacyToken != "" {
		h.upgradeLegacyToken(ctx, prin.legacyToken, sha256Hex(prin.legacyToken), "")
	}
	recordTokenUse(ctx, h, prin)

	// Flatten LAST. Every axis has had its say on the roles by now, so a
	// wildcard expands only if the role carrying it survived all of them —
	// which is what stops a superadmin of one organization passing checks in
	// the next.
	return &pb.AuthResp{
		PermissionIds:  prin.effectivePermissions(h.Lock),
		UserId:         userID,
		Scopes:         scopes,
		Labels:         labels,
		SessionTokenId: prin.tokenID,
		DeviceId:       prin.deviceThumbprint,
	}, nil
}

// presentedToken strips the scheme off the auth header. A token may come
// under DPoP (RFC 9449, a bound token with a proof — viaDPoP) or under the
// configured scheme (Bearer); checkTokenBinding refuses the latter once the
// token resolves, with a code that tells the client to sign its requests. A
// configured scheme of "" takes the header as the bare token.
func (h *AuthServiceHandler) presentedToken(raw string) (token string, viaDPoP bool, err error) {
	switch {
	// The scheme is case-insensitive (RFC 9110 §11.1).
	case len(raw) > len(dpopScheme) && strings.EqualFold(raw[:len(dpopScheme)], dpopScheme) && raw[len(dpopScheme)] == ' ':
		token, viaDPoP = raw[len(dpopScheme)+1:], true
	case h.Scheme == "":
		token = raw
	case strings.HasPrefix(raw, h.Scheme+" "):
		token = strings.TrimPrefix(raw, h.Scheme+" ")
	default:
		return "", false, errAuthnSchemeMismatch
	}
	if token == "" {
		return "", false, errAuthnTokenEmpty
	}
	return token, viaDPoP, nil
}

// SignIn is the canonical email+password→bearer-token flow.
// Three steps in a fixed sequence with one opaque failure mode:
//
//  1. GetUserByEmail resolves the principal (and returns the
//     stored password hash).
//  2. PasswordHash.VerifyAndRotate compares against the plain
//     password. Rotation update-fn is nil for v1 — the plugin
//     doesn't expose an UpdateUserPasswordHash mutation in its
//     client surface yet; rehash-on-login is parked.
//  3. IssueToken mints the bearer token.
//
// Anti-enumeration: every failure path emits the same status.
// VerifyAndRotate's `err` return is non-fatal when ok=true (a
// failed rehash doesn't invalidate the auth) — discarded here
// since the plugin doesn't yet have an UpdateUserPasswordHash
// mutation to apply the new hash anyway.
func (h *AuthServiceHandler) SignIn(ctx context.Context, req *pb.SignInReq) (*pb.SignInResp, error) {
	// The device key first: without a proof there is no token to issue, and
	// refusing before the lookup costs nothing and says nothing about the
	// address.
	thumbprint, err := mintThumbprint(ctx)
	if err != nil {
		return nil, err
	}
	userResp, err := h.Query.GetUserByEmail(ctx, &pb.GetUserByEmailReq{Email: normalizeEmail(req.GetEmail())})
	if err != nil {
		// Anti-enumeration: a missing account must cost the same as a wrong
		// password. Without this, GetUserByEmail returns fast (no argon2) for a
		// non-existent user but the found path pays the ~argon2 derivation — a
		// timing oracle that enumerates valid emails. Run a throwaway verify so
		// the response time doesn't leak account existence. (The opaque
		// Unauthenticated code is already identical on both paths.)
		signInDummyVerify(h, req.GetPassword())
		return nil, UnauthenticatedSignIn(err)
	}
	user := userResp.GetUser()

	ok, _, _ := h.PasswordHash.VerifyAndRotate(user.GetPasswordHash(), req.GetPassword(), nil)
	if !ok {
		return nil, UnauthenticatedSignIn(errAuthnPasswordMismatch)
	}

	// Disabled-account gate (user_admin feature; no-op otherwise).
	// Checked AFTER the password verify so a disabled account is
	// indistinguishable from a wrong password (same opaque
	// Unauthenticated) — a pre-password check would leak "this account
	// is disabled" to anyone who knows the email.
	// Machine accounts never sign in with a password. Checked beside the
	// disabled gate, after the password verify, so a bot is indistinguishable
	// from a wrong password (same opaque Unauthenticated).
	if err := signInBotGate(user); err != nil {
		return nil, UnauthenticatedSignIn(err)
	}
	if err := signInDisabledGate(user); err != nil {
		return nil, UnauthenticatedSignIn(err)
	}

	// Register the device the token will be bound to, so the 2FA gate can
	// make its new-device decision (and bind the challenge to this key). A revoked device is refused here, after
	// the password: only someone who knows it learns the device's state.
	dev, err := mintDevice(ctx, h, user.GetId(), thumbprint)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	deviceID, trusted := dev.id, dev.trusted

	// Second-factor gate (two_factor feature; no-op otherwise). When it
	// raises a challenge it returns the mfa_required response and we
	// stop here WITHOUT issuing a token — VerifyMfa completes the login.
	if resp, challenged, gErr := signInMfaGate(ctx, h, user, thumbprint, trusted); gErr != nil {
		return nil, Unauthenticated(gErr)
	} else if challenged {
		return resp, nil
	}

	// Trust is renewed for a device that already has it, never granted here:
	// reaching this line means no second factor was asked for — either the
	// device is trusted, or `two_factor` is off and there is no factor to
	// pass. Granting trust on the password alone would let every device that
	// ever signed in skip the factor once `two_factor_scope=new_devices` is
	// switched on. A device earns trust by passing VerifyMfa.
	var trustCutoff *timestamppb.Timestamp
	if trusted {
		trustCutoff = dev.trustCutoff
	}
	token, err := issueSession(ctx, h, user.GetId(), deviceID, trustCutoff)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	return &pb.SignInResp{
		UserId: user.GetId(),
		Token:  token,
	}, nil
}

// signInDisabledGate rejects a soft-disabled account on SignIn. Base
// no-op: `User.disabled_at` is gated behind the `user_admin` feature, so
// it is ABSENT from the consumer's generated User when that feature is
// off — the always-compiled SignIn handler must not name the field.
// handlers/user_admin.go (staged only under `user_admin`) overrides this
// via init() to check user.GetDisabledAt(), mirroring the signInMfaGate
// seam. Returning a non-nil error makes SignIn emit the opaque
// Unauthenticated (anti-enumeration) — the caller never learns the
// account exists but is disabled.
var signInDisabledGate = func(user *pb.User) error { return nil }

// errAuthnUserDisabled is the internal cause behind the opaque
// Unauthenticated a disabled account gets on SignIn. Never surfaced to
// the caller (SignIn maps every failure to the same opaque code) — it
// exists for logs / tests.
// Declared here, with every feature, because oauthRefusal names it.
var errAuthnUserDisabled = errors.New("account disabled")

// signInBotGate refuses a password sign-in for a MACHINE account.
//
// ⚠️ This is the enforcement that makes `User.kind` a control rather than a
// label. A bot's `password_hash` is empty and `passwordhash.Verify` already
// refuses an empty stored hash — but that is luck, not design: the column is a
// plain string with no null, so "bot" is an empty value rather than an absent
// one, and the first `password_change` against a bot would hand it a working
// password and open the door the empty hash was holding shut.
//
// A bot acts through an API token an admin minted for it, and through nothing
// else. Same seam shape as signInDisabledGate above and for the same reason:
// `kind` is field-gated on `service_account`, so it is ABSENT from the
// consumer's generated User when the feature is off and the always-compiled
// handler must not name it. handlers/service_account.go installs the real one
// via init().
//
// Returns a non-nil error so SignIn emits the opaque Unauthenticated: a caller
// must not learn that an address belongs to a bot.
var signInBotGate = func(user *pb.User) error { return nil }

// refuseUnsignableAccount runs SignIn's account gates — disabled, machine — for
// a path that issues a session to an EXISTING account without passing through
// SignIn's lookup: the second sign-in step, the OAuth callback, the CLI
// exchange. Each of those is reached with a user id decided earlier (a
// challenge, a linked identity, a code minted from a session), and the account
// may have changed since: SignIn refused a disabled account, but a challenge
// opened before the disable would still issue a session. Refused with the
// opaque Unauthenticated, as SignIn is.
func refuseUnsignableAccount(ctx context.Context, h *AuthServiceHandler, userID string) error {
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return Unauthenticated(err)
	}
	if err := signInDisabledGate(got.GetUser()); err != nil {
		return Unauthenticated(err)
	}
	if err := signInBotGate(got.GetUser()); err != nil {
		return Unauthenticated(err)
	}
	return nil
}

// normalizeEmail canonicalises an email for both storage and lookup: trim +
// lowercase. Emails are treated case-insensitively in practice, but the
// type:EMAIL field is a plain (case-sensitive) string unique constraint — so
// without normalisation "Foo@X.com" and "foo@x.com" would create two accounts
// and a cross-case sign-in would miss the row. Applied at every CreateUser /
// GetUserByEmail boundary (signup, signin, oauth) so the canonical form is
// consistent across writes and reads.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

var (
	signInDummyOnce sync.Once
	signInDummyHash string
)

// signInDummyVerify runs a throwaway password verification on SignIn's
// user-not-found path so the response time doesn't reveal whether the account
// exists (timing-based user enumeration). The dummy hash is computed once with
// the configured params — Verify derives its argon2 cost from the STORED hash's
// params, so this matches a real verify's derivation time. A `var` so tests can
// assert SignIn invokes it without paying the argon2 cost.
var signInDummyVerify = func(h *AuthServiceHandler, plain string) {
	signInDummyOnce.Do(func() {
		signInDummyHash, _ = h.PasswordHash.Hash("w17-anti-enumeration-dummy-secret")
	})
	if signInDummyHash != "" {
		_, _, _ = h.PasswordHash.VerifyAndRotate(signInDummyHash, plain, nil)
	}
}

// SignUp (the register-and-issue-token flow) + its signupCreateUser seam
// live in handlers/signup.go, staged only under the sign_up_turnkey
// feature — alongside the pb.SignUpReq/Resp types gated by the same
// feature. Keeping them out of this always-compiled file lets an
// activation omit sign_up_turnkey (e.g. an admin auth realm that seeds
// accounts) without a dangling reference.

// WhoAmI returns the authenticated principal so the FE can confirm
// a persisted token is still live. By the time the request reaches
// this handler the gateway's auth_method (Authenticate) has already
// validated the bearer per-request — an invalid/absent token 401s
// at the gateway before dispatch — and threaded the principal both
// as the `x-w17-user` AuthResp envelope (always) and, when the
// project declares a `user_id` data scope, as `x-w17-scope-user_id`.
// The handler echoes whichever is present; no storage round-trip
// (the metadata value is itself the proof).
//
// The scope key is preferred (cheap string read) with a fallback to
// decoding the always-present envelope, so WhoAmI works in projects
// with NO data scopes — there the scope key is never threaded.
//
// The fail-closed guard covers direct gRPC callers that bypass the
// gateway (no metadata at all) — same opaque Unauthenticated as the
// rest of the surface.
func (h *AuthServiceHandler) WhoAmI(ctx context.Context, req *pb.WhoAmIReq) (*pb.WhoAmIResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp := &pb.WhoAmIResp{UserId: userID}
	whoAmIEnrich(ctx, h, userID, resp)
	return resp, nil
}

// whoAmIEnrich fills the org half of WhoAmI. Base tier: a no-op.
//
// The org fields exist on this message only under `org_membership`, and the
// queries that answer them exist only there too, so the base build must not
// name either. handlers/org_membership.go swaps in the real one when that
// feature is staged — the same seam shape signupAssignRoles uses for rbac,
// and for the same reason: a staged file may reference gated queries, this
// one may not.
var whoAmIEnrich = func(ctx context.Context, h *AuthServiceHandler, userID string, resp *pb.WhoAmIResp) {
}

// Logout revokes the caller's CURRENT session token — the base-tier
// counterpart to SignIn, available without the `devices` feature. It
// reads the authenticated principal (user_id) plus the session_token_id
// the gateway threaded in the auth envelope and revokes exactly that one
// SESSION token via RevokeSessionToken (ownership guarded in the mutation:
// id AND user_id; reason LOGOUT, the caller as revoked_by). The row stays.
// The raw bearer never reaches here — only the resolved session token id
// does, so it's always a session token (the DQL drops the token_type
// filter — that column is api_token-gated).
//
// Idempotent about the SESSION, not about the caller: a token that was already
// revoked still gets a clean success, because "this session is already gone" is
// nothing left to do.
//
// ⛔ A caller with NO resolvable session token — an API-token bearer, or a
// direct gRPC call — is REFUSED (FailedPrecondition), not waved through (since
// auth v0.1.0-rc.4). The reasoning for the refusal is at the branch
// itself; the short version is that "I was not told which session" is not
// idempotence.
//
// "Log out everywhere / other devices" is the `devices` feature's
// RevokeAllDevices, not this.
func (h *AuthServiceHandler) Logout(ctx context.Context, _ *pb.LogoutReq) (*pb.LogoutResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	tokenID := callerSessionTokenID(ctx)
	if tokenID == "" {
		// ⛔ REFUSED.
		//
		// An empty id means Logout does not know WHICH session to end. That is
		// not idempotence — idempotence is "this session is already gone, so
		// there is nothing to do", and the handler below says so by treating a
		// zero-row revoke as success. This is "I was not told which one", and
		// answering OK to that is a claim that is not true.
		//
		// What an OK would cost: a facade wrapping Logout whose VerifyRes
		// carries fields 1-3 (the trio documented as the shared contract) and
		// not field 4 answers every sign-out 200, the UI says "signed out", the
		// app drops the cookie — and the token keeps working until it expires.
		// Only a check that takes the token BEFORE signing out and tries it
		// after sees that; a check on the status code passes. On a shared or
		// stolen machine that is the difference between logged out and logged
		// in without it showing.
		//
		// The envelope cannot tell the two blank cases apart — AuthResp carries
		// no token type — so the refusal names both. An API-token bearer has no
		// session to end and was ALSO getting a false OK; RevokeApiToken is the
		// operation for that, and being told so beats being told nothing.
		return nil, status.Error(codes.FailedPrecondition,
			"logout: the request carries no session token id, so there is no session to end — "+
				"either the caller is an API-token bearer (use RevokeApiToken; an API token is not a session), "+
				"or the auth envelope reaching this handler is missing AuthResp.session_token_id (field 4), "+
				"which a hand-written facade VerifyRes must carry for logout to revoke anything")
	}
	if _, err := h.Mutation.RevokeSessionToken(ctx, &pb.RevokeSessionTokenReq{
		TokenId:   tokenID,
		UserId:    userID,
		TokenType: pb.TokenType_TOKEN_TYPE_SESSION,
	}); err != nil {
		// Already-revoked token (zero rows → NotFound) is an idempotent
		// logout success; anything else propagates.
		if e := notFoundOK(err); e != nil {
			return nil, e
		}
	}
	return &pb.LogoutResp{}, nil
}

// notFoundOK turns a storage NotFound into success. The write primitives
// RETURNING a row map zero matched rows to NotFound (single-row scan →
// sql.ErrNoRows), but revoking something already revoked — a stale device,
// a token signed out twice — or clearing a TOTP secret that was never
// enrolled is a no-op, not an error. Lives here (always-compiled) so both handlers/devices.go and
// handlers/mfa.go use it without a cross-feature dependency.
func notFoundOK(err error) error {
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

// callerUserID reads the bearer-authenticated principal the gateway
// threaded into x-w17-scope-user_id metadata (same source as WhoAmI) —
// the self-service management RPCs (api_token, devices, two_factor) act on
// the calling user's own resources. Fails closed (opaque Unauthenticated
// cause) for direct gRPC callers that bypass the gateway and carry no
// scope. Lives here (always-compiled) because several independent feature
// files depend on it — keeping it in any one feature's file would break a
// bundle that enables that consumer feature but not the file's owner.
func callerUserID(ctx context.Context) (string, error) {
	// principal.UserID applies the same dual-source recovery this used to
	// hand-roll: the x-w17-scope-user_id fast path, then the always-threaded
	// x-w17-user envelope (the gateway only threads the scope key when the
	// surface declares a `user_id` data scope, so a project with no scoped
	// model — the common case for the management RPCs — would 401 without
	// the fallback). Collapse its sentinel to ours so the authn-flow
	// auditor still sees every path converge on Unauthenticated.
	uid, err := principal.UserID(ctx, &pb.AuthResp{})
	if err != nil {
		return "", errAuthnNoPrincipal
	}
	return uid, nil
}

// callerSessionTokenID recovers the id of the UserToken the caller's
// bearer resolved to, from the gateway's x-w17-user envelope (Authenticate
// stamps AuthResp.session_token_id). Returns "" on any miss.
//
// ⚠️ Logout refuses on that empty string rather than NO-OP: a no-op would
// spare an API-token bearer an error, at the cost of a real session's logout
// answering OK having revoked nothing — see the note at its call site.
// Reads the envelope, never the raw bearer (which never reaches handlers).
func callerSessionTokenID(ctx context.Context) string {
	var ar pb.AuthResp
	if err := principal.Envelope(ctx, &ar); err != nil {
		return ""
	}
	return ar.GetSessionTokenId()
}

// errCallerNotASession refuses an API token where only a signed-in session may
// act: creating another credential. The operator's copy; the person reads
// MsgSessionRequired.
var errCallerNotASession = errors.New("this operation needs a signed-in session; an API token cannot create credentials")

// requireSessionCaller refuses a caller that did not authenticate with a
// session token.
//
// An operation that creates a credential (an API token, a CLI session, an
// authenticator or its recovery codes, a trusted CLI callback) must not be
// reachable from an API token: the new credential is minted from the holder's
// account, not from the caller's narrowed permissions, so a token limited to
// one permission would come out of it with all of them, a CLI exchange would
// turn it into a session, and an enrolled authenticator would hand the
// account's second factor to whoever holds the token. Authenticate sets
// session_token_id only for a session-realm token and leaves it empty for any
// other, which is what tells the two apart here. An envelope without it (an
// authenticator other than this plugin's) is refused too: it cannot show that
// the caller is a session.
func requireSessionCaller(ctx context.Context) error {
	if callerSessionTokenID(ctx) == "" {
		return refusal(ctx, codes.PermissionDenied, errCallerNotASession.Error(),
			CodeSessionRequired, "", MsgSessionRequired, nil)
	}
	return nil
}

// intersectInt32 returns the elements of `a` that also appear in `b`,
// preserving `a`'s order and de-duplicating.
//
// Lives here, in the always-compiled file, because BOTH narrowing axes
// need it: `api_token` narrows realm permissions to a token's declared
// subset, and `org_membership` narrows them to the active organization.
// Keeping it in either feature's file would make that feature's presence
// a build-time prerequisite of the other's.
func intersectInt32(a, b []int32) []int32 {
	allow := make(map[int32]struct{}, len(b))
	for _, x := range b {
		allow[x] = struct{}{}
	}
	out := make([]int32, 0, len(a))
	seen := make(map[int32]struct{}, len(a))
	for _, x := range a {
		if _, ok := allow[x]; !ok {
			continue
		}
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// runScopeDecorators runs the feature-staged scope decorators in order and
// turns the first failure into an authentication refusal. A decorator that
// already said what kind of refusal it is (UnauthenticatedOrgNotMember) keeps
// its words; wrapping it again would drop them back to the generic answer.
func runScopeDecorators(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error {
	for _, dec := range scopeDecorators {
		if err := dec(ctx, h, userID, headers, scopes, labels); err != nil {
			var classified *authnError
			if errors.As(err, &classified) {
				return classified
			}
			return Unauthenticated(err)
		}
	}
	return nil
}
