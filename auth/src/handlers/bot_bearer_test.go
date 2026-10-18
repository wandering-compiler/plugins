package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// device/bot-bearer: a machine account's token without a key.

// Without a key, IssueBotToken mints a bearer token: the bot-bearer prefix,
// bound to no device (no key is registered, the account is not even locked
// for one), stored as its hash only, always with an expiry — the 90-day
// fallback when the deployment's default is "never" — and recorded with the
// operator's device as approver and one BOT_TOKEN history row with no device.
func TestIssueBotToken_WithoutAKeyMintsAnExpiringBearerToken(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	laptop := s.put("op-1", testJKT, &pb.Device{})
	h := &AuthServiceHandler{Query: s, Mutation: s, APITokenDefaultTTLHours: 0}
	hist := keepHistory(h)
	before := time.Now()
	resp, err := h.IssueBotToken(operatorCtx("op-1", testJKT), &pb.IssueBotTokenReq{UserId: "bot-1", Name: "deploy", PermissionSubset: []int32{7}})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetBearer() || resp.GetDeviceId() != "" || !strings.HasPrefix(resp.GetToken(), botBearerPrefix) || len(resp.GetToken()) != len(botBearerPrefix)+bearerTokenLen {
		t.Fatalf("resp = %+v, want a prefixed bearer token bound to no key", resp)
	}
	if len(s.bearerMinted) != 1 || len(s.minted) != 0 || len(s.rows) != 1 {
		t.Fatalf("bearer %d, bound %d, devices %v: want one bearer mint and no device", len(s.bearerMinted), len(s.minted), s.rows)
	}
	m := s.bearerMinted[0]
	if m.GetTokenHash() != sha256Hex(resp.GetToken()) || m.GetUserId() != "bot-1" || m.GetTokenType() != pb.TokenType_TOKEN_TYPE_API || m.GetName() != "deploy" || m.GetDeviceId() != "" || m.GetKeyThumbprint() != "" {
		t.Errorf("minted %+v", m)
	}
	if m.GetApprovedByDeviceId() != laptop.GetId() || m.GetCreatedBy() != "op-1" {
		t.Errorf("approver %q / creator %q, want the operator's device and the operator", m.GetApprovedByDeviceId(), m.GetCreatedBy())
	}
	exp := m.GetExpiresAt().AsTime()
	wantExp := before.Add(time.Duration(defaultAPITokenTTLHours) * time.Hour)
	if exp.Before(wantExp.Add(-time.Minute)) || exp.After(wantExp.Add(time.Minute)) || !resp.GetExpiresAt().AsTime().Equal(exp) {
		t.Errorf("expires_at = %v, want ~%v (never is not an answer for a bearer token)", exp, wantExp)
	}
	if strings.Join(s.order, ",") != "mint-bearer" {
		t.Errorf("order = %v, want no key lookup or registration", s.order)
	}
	hist.one(t, "IssueBotToken bearer", want{
		method: pb.SignInMethod_SIGN_IN_METHOD_BOT_TOKEN, outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK,
		user: "bot-1", address: "ci@machines.example",
	})
}

// A bearer token never lives more than maxBotBearerTTL: an expiry asked
// beyond it is refused on the field, a longer deployment default is cut to it,
// and an expiry within it is kept as asked.
func TestIssueBotToken_ABearerTokenExpiresWithinAYear(t *testing.T) {
	withoutOrgs(t)
	op := operatorCtx("op-1", testJKT)

	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.IssueBotToken(op, &pb.IssueBotTokenReq{UserId: "bot-1", ExpiresAt: timestamppb.New(time.Now().Add(maxBotBearerTTL + time.Hour))})
	if status.Code(err) != codes.InvalidArgument || detailOf(t, err).GetCode() != "TOKEN_EXPIRY_TOO_FAR" || detailOf(t, err).GetField() != "expires_at" {
		t.Fatalf("err = %v, want TOKEN_EXPIRY_TOO_FAR on expires_at", err)
	}
	if len(s.bearerMinted) != 0 {
		t.Fatal("a refused expiry minted a token")
	}

	h.APITokenDefaultTTLHours = 2 * 366 * 24
	resp, err := h.IssueBotToken(op, &pb.IssueBotTokenReq{UserId: "bot-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(resp.GetExpiresAt().AsTime()); got > maxBotBearerTTL || got < maxBotBearerTTL-time.Minute {
		t.Errorf("a two-year default gave %v, want the ceiling %v", got, maxBotBearerTTL)
	}

	asked := timestamppb.New(time.Now().Add(30 * 24 * time.Hour))
	resp, err = h.IssueBotToken(op, &pb.IssueBotTokenReq{UserId: "bot-1", ExpiresAt: asked})
	if err != nil || !resp.GetExpiresAt().AsTime().Equal(asked.AsTime()) {
		t.Fatalf("an expiry within a year: %v, %v; want it kept", resp.GetExpiresAt(), err)
	}
}

// The account checks come first without a key too: a person and an unknown
// account are refused and nothing is minted. (The disabled bot, another
// organization's bot, a bot above the operator and an API-token caller are
// refused keyless too — in their own tests, beside the keyed case.)
func TestIssueBotToken_ABearerTokenIsForAMachineAccountOnly(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.IssueBotToken(operatorCtx("op-1", ""), &pb.IssueBotTokenReq{UserId: "nobody"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown account: %v", err)
	}
	s.bot.Kind = pb.AccountKind_HUMAN
	if _, err := h.IssueBotToken(operatorCtx("op-1", ""), &pb.IssueBotTokenReq{UserId: "bot-1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a person: %v", err)
	}
	if len(s.bearerMinted) != 0 {
		t.Fatalf("minted %v", s.bearerMinted)
	}
}

// ── Authenticate ─────────────────────────────────────────────

// bearerLookup resolves one token (`known`) through the realm-aware resolver
// as a row with the given flags, and answers one ended token (`expired`).
type bearerLookup struct {
	pb.AuthQueryClient
	known, expired string
	bearer         bool
	kind           pb.AccountKind
	realm          pb.TokenType
	thumb          string
	mcp            bool
	disabled       bool
	lookups        int
}

func (q *bearerLookup) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	q.lookups++
	if in.GetTokenHash() != sha256Hex(q.known) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetTokenWithTypeResp{UserId: "bot-1", TokenId: "tok-b", TokenType: q.realm, StoredTokenHash: in.GetTokenHash(),
		User: q.user(), DeviceThumbprint: q.thumb, McpOnly: q.mcp, Bearer: q.bearer}, nil
}

func (q *bearerLookup) user() *pb.User {
	u := &pb.User{Id: "bot-1", Kind: q.kind}
	if q.disabled {
		u.DisabledAt = timestamppb.Now()
	}
	return u
}

func (q *bearerLookup) GetExpiredTokenWithType(_ context.Context, in *pb.GetExpiredTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	if q.expired == "" || in.GetTokenHash() != sha256Hex(q.expired) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetExpiredTokenWithTypeResp{ExpiresAt: timestamppb.New(expiredAt), TokenType: q.realm, DeviceThumbprint: q.thumb, Bearer: q.bearer}, nil
}

func (q *bearerLookup) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

func (q *bearerLookup) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	return &pb.GetTokenPermissionSubsetResp{}, nil
}

// aBotBearer is a live bearer token row of a machine account.
func aBotBearer(token string) *bearerLookup {
	return &bearerLookup{known: token, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API}
}

func bearerAuthenticate(t *testing.T, resolver func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error), q pb.AuthQueryClient, req *pb.AuthReq) (*pb.AuthResp, *touchRecorder, error) {
	t.Helper()
	return bearerAuthenticateOn(t, false, resolver, q, req)
}

// bearerAuthenticateOn is bearerAuthenticate, on the admin plane when admin.
func bearerAuthenticateOn(t *testing.T, admin bool, resolver func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error), q pb.AuthQueryClient, req *pb.AuthReq) (*pb.AuthResp, *touchRecorder, error) {
	t.Helper()
	prevDec, prevNarrow, prevRes := scopeDecorators, grantNarrowers, resolvePrincipal
	t.Cleanup(func() { scopeDecorators, grantNarrowers, resolvePrincipal = prevDec, prevNarrow, prevRes })
	scopeDecorators, grantNarrowers, resolvePrincipal = nil, nil, resolver
	rec := &touchRecorder{}
	h := &AuthServiceHandler{Query: q, Mutation: rec, HeaderName: "Authorization", Scheme: "Bearer"}
	call := h.Authenticate
	if admin {
		call = h.AuthenticateAdmin
	}
	resp, err := call(context.Background(), req)
	return resp, rec, err
}

func bearerReq(token string) *pb.AuthReq {
	return &pb.AuthReq{Headers: map[string]string{"authorization": "Bearer " + token}}
}

var botTok = botBearerPrefix + strings.Repeat("a", bearerTokenLen)

// A machine account's bearer token passes without a proof, answers no device
// and is recorded as used.
func TestAuthenticate_ABotBearerTokenPassesWithoutAProof(t *testing.T) {
	resp, rec, err := bearerAuthenticate(t, resolvePrincipalRealmAware, aBotBearer(botTok), bearerReq(botTok))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetUserId() != "bot-1" || resp.GetDeviceId() != "" {
		t.Errorf("AuthResp = %+v, want the bot and no device", resp)
	}
	if len(rec.touches) != 1 {
		t.Errorf("touches = %d, want the use recorded", len(rec.touches))
	}
}

// The prefix authorizes nothing: a proofless request with a prefixed token
// passes only for a row flagged `bearer`, an API token of a machine account
// bound to no device and not an MCP token. Every other case — and an unknown
// prefixed token — is the opaque refusal and records nothing. Through the
// session resolver (no service_account) nothing is a bearer token.
func TestAuthenticate_OnlyAFlaggedBotTokenPassesWithoutAProof(t *testing.T) {
	for name, q := range map[string]*bearerLookup{
		"no bearer flag":   {known: botTok, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API},
		"a person's token": {known: botTok, bearer: true, kind: pb.AccountKind_HUMAN, realm: pb.TokenType_TOKEN_TYPE_API},
		"a session token":  {known: botTok, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_SESSION},
		"bound to a key":   {known: botTok, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API, thumb: testJKT},
		"an MCP token":     {known: botTok, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API, mcp: true},
		"unknown":          {known: "other", bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API},
	} {
		_, rec, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(botTok))
		t.Run(name, func(t *testing.T) {
			wantOpaque(t, err)
			if len(rec.touches) != 0 {
				t.Error("a refused request was recorded as used")
			}
		})
	}
	sessionQ := &bindingQuery{known: botTok}
	_, _, err := bearerAuthenticate(t, resolvePrincipalSession, sessionQ, bearerReq(botTok))
	t.Run("session resolver", func(t *testing.T) { wantOpaque(t, err) })
}

// Without the prefix nothing changes: a proofless request is refused with
// DEVICE_PROOF_REQUIRED before the lookup, even for a row flagged `bearer`.
// With the prefix, the DPoP scheme or the MCP surface take their usual paths:
// a bearer token is no bound token and no MCP token.
func TestAuthenticate_ABearerTokenTakesNoOtherPath(t *testing.T) {
	plain := strings.Repeat("a", bearerTokenLen)
	q := aBotBearer(plain)
	_, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(plain))
	wantDeviceRefusal(t, err, CodeDeviceProofRequired)
	if q.lookups != 0 {
		t.Fatalf("an unprefixed token was looked up (%d) without a proof", q.lookups)
	}
	for name, req := range map[string]*pb.AuthReq{
		"under DPoP with a proof": boundAuthReq(botTok, testJKT),
		"on the MCP surface":      mcpAuthReq(botTok),
	} {
		_, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, aBotBearer(botTok), req)
		t.Run(name, func(t *testing.T) { wantOpaque(t, err) })
	}
	_, _, err = bearerAuthenticate(t, resolvePrincipalRealmAware, aBotBearer(botTok), &pb.AuthReq{Headers: map[string]string{"authorization": "DPoP " + botTok}})
	wantDeviceRefusal(t, err, CodeDeviceProofRequired)
}

// A bearer token never opens the admin plane, and a build without machine
// accounts never looks one up: both refuse it like any proofless request,
// before the lookup.
func TestAuthenticate_ABearerTokenIsRefusedOnTheAdminPlaneAndWithoutMachineAccounts(t *testing.T) {
	q := aBotBearer(botTok)
	_, _, err := bearerAuthenticateOn(t, true, resolvePrincipalRealmAware, q, bearerReq(botTok))
	wantDeviceRefusal(t, err, CodeDeviceProofRequired)
	if q.lookups != 0 {
		t.Fatalf("admin plane: looked up %d times", q.lookups)
	}

	prev := serviceAccountStaged
	t.Cleanup(func() { serviceAccountStaged = prev })
	serviceAccountStaged = false
	q = aBotBearer(botTok)
	_, _, err = bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(botTok))
	wantDeviceRefusal(t, err, CodeDeviceProofRequired)
	if q.lookups != 0 {
		t.Fatalf("without service_account: looked up %d times", q.lookups)
	}
}

// A disabled machine account's bearer token is the opaque refusal.
func TestAuthenticate_ADisabledBotsBearerTokenIsRefused(t *testing.T) {
	q := aBotBearer(botTok)
	q.disabled = true
	_, rec, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(botTok))
	wantOpaque(t, err)
	if len(rec.touches) != 0 {
		t.Error("a disabled bot's request was recorded as used")
	}
}

// An ended bearer token says so to whoever presents it — its holder — and an
// ended prefixed token that is not one stays the opaque refusal.
func TestAuthenticate_AnEndedBearerTokenSaysSo(t *testing.T) {
	q := &bearerLookup{expired: botTok, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API}
	_, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(botTok))
	wantDeviceRefusal(t, err, CodeSessionExpired)

	for name, q := range map[string]*bearerLookup{
		"not flagged":        {expired: botTok, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API},
		"flagged but bound":  {expired: botTok, bearer: true, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API, thumb: testJKT},
		"not flagged, bound": {expired: botTok, kind: pb.AccountKind_BOT, realm: pb.TokenType_TOKEN_TYPE_API, thumb: testJKT},
	} {
		_, _, err = bearerAuthenticate(t, resolvePrincipalRealmAware, q, bearerReq(botTok))
		t.Run(name, func(t *testing.T) { wantOpaque(t, err) })
	}
}

func TestIsBotBearerToken(t *testing.T) {
	for tok, want := range map[string]bool{botTok: true, botBearerPrefix: false, "": false, "W17BOT_x": false, "xw17bot_x": false} {
		if got := isBotBearerToken(tok); got != want {
			t.Errorf("isBotBearerToken(%q) = %v", tok, got)
		}
	}
}

// ── the statements ──────────────────────────────────────────

// The bearer mint is IssueApiToken — ApiTokenCreated's one emit site — with
// the flag written under service_account only; both lookups read it under
// service_account only.
func TestBotBearerStatements(t *testing.T) {
	body := mutationRPCBody(t, "IssueApiToken")
	for _, want := range []string{`"?feature(service_account) bearer = :bearer "`, `event: "ApiTokenCreated"`} {
		if !strings.Contains(body, want) {
			t.Errorf("IssueApiToken lacks %s", want)
		}
	}
	for _, rpc := range []string{"GetTokenWithType", "GetExpiredTokenWithType"} {
		if !strings.Contains(queryRPCBody(t, rpc), `?feature(service_account) t.bearer AS bearer`) {
			t.Errorf("%s does not read the bearer flag", rpc)
		}
	}
}
