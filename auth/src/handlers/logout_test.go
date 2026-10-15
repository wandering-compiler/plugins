package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Base-tier logout (no `devices` feature): revoke the
// caller's CURRENT session token, identified by the session_token_id
// Authenticate threads in the auth envelope (never the raw bearer).

type logoutMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	revokeReq *pb.RevokeSessionTokenReq
	revokeErr error
}

func (m *logoutMock) RevokeSessionToken(_ context.Context, in *pb.RevokeSessionTokenReq, _ ...grpc.CallOption) (*pb.RevokeSessionTokenResp, error) {
	m.revokeReq = in
	if m.revokeErr != nil {
		return nil, m.revokeErr
	}
	return &pb.RevokeSessionTokenResp{TokenId: in.GetTokenId(), UserId: in.GetUserId()}, nil
}

// ctxWithEnvelope sets the gateway's x-w17-user envelope (base64 AuthResp)
// carrying user_id + session_token_id, exactly as Authenticate stamps it.
func ctxWithEnvelope(t *testing.T, userID, tokenID string) context.Context {
	t.Helper()
	raw, err := proto.Marshal(&pb.AuthResp{UserId: userID, SessionTokenId: tokenID})
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

func TestLogout_RevokesCurrentSession(t *testing.T) {
	m := &logoutMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(ctxWithEnvelope(t, "u1", "tok-1"), &pb.LogoutReq{}); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if m.revokeReq == nil {
		t.Fatal("Logout did not call RevokeSessionToken")
	}
	if m.revokeReq.GetTokenId() != "tok-1" || m.revokeReq.GetUserId() != "u1" {
		t.Errorf("revoke guard wrong: %+v (want token tok-1 / user u1)", m.revokeReq)
	}
	if m.revokeReq.GetTokenType() != pb.TokenType_TOKEN_TYPE_SESSION {
		t.Errorf("revoke token_type = %v, want SESSION (logout must never revoke an API token)", m.revokeReq.GetTokenType())
	}
}

// No session_token_id in the envelope → REFUSE, and revoke nothing.
//
// ⚠️ An idempotent NO-OP here, on the reasoning that an API-token bearer
// should not get an error, lets a broken facade ship: one whose VerifyRes
// carries fields 1-3 and not field 4 answers every sign-out 200 with nothing
// revoked — the UI says "signed out", the cookie goes, and the token keeps
// working until it expires.
//
// The distinction the old behaviour lost: "this session is already gone"
// (idempotent, and still a success — see the NotFound arm below) versus "I was
// not told which session", which is a question, not a no-op.
func TestLogout_NoSessionToken_Refused(t *testing.T) {
	m := &logoutMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.Logout(ctxWithEnvelope(t, "u1", ""), &pb.LogoutReq{})
	if err == nil {
		t.Fatal("logout answered OK with no session id — it revoked nothing and said it had")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %s, want FailedPrecondition — the caller IS authenticated; what is missing is the envelope field", got)
	}
	// The envelope cannot say WHICH blank case this is (AuthResp carries no
	// token type), so the message has to name both or it sends half its
	// readers the wrong way.
	for _, want := range []string{"session_token_id", "RevokeApiToken", "facade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q; got: %v", want, err)
		}
	}
	if m.revokeReq != nil {
		t.Errorf("must not revoke when there is no session token id; got %+v", m.revokeReq)
	}
}

// Deleting an already-revoked / expired token (zero rows → NotFound) is an
// idempotent logout success.
func TestLogout_AlreadyRevoked_Idempotent(t *testing.T) {
	m := &logoutMock{revokeErr: status.Error(codes.NotFound, "no rows")}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(ctxWithEnvelope(t, "u1", "tok-1"), &pb.LogoutReq{}); err != nil {
		t.Fatalf("logout of an already-revoked session must succeed, got %v", err)
	}
}

// A real (non-NotFound) mutation error must propagate, not be swallowed.
func TestLogout_MutationError_Propagates(t *testing.T) {
	m := &logoutMock{revokeErr: errors.New("db down")}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(ctxWithEnvelope(t, "u1", "tok-1"), &pb.LogoutReq{}); err == nil {
		t.Fatal("a non-NotFound mutation error must propagate")
	}
}

// No caller identity at all → Unauthenticated.
func TestLogout_NoCaller_Unauthenticated(t *testing.T) {
	m := &logoutMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(context.Background(), &pb.LogoutReq{}); err == nil {
		t.Fatal("expected Unauthenticated with no caller metadata")
	}
}

// The other half of the wiring: principal resolution must return the
// session's token_id, which Authenticate stamps into
// AuthResp.session_token_id (a one-line assignment) so the gateway
// envelope carries it to Logout. (The test binary's resolvePrincipal is
// the realm-aware override from apitoken.go's init.)
func TestResolvePrincipalRealmAware_ReturnsTokenID(t *testing.T) {
	m := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{StoredTokenHash: "stored", UserId: "u1", TokenId: "tok-9", TokenType: pb.TokenType_TOKEN_TYPE_SESSION},
		realmPerms: []int32{1, 2},
	}
	h := &AuthServiceHandler{Query: m}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, tokID := prin.userID, prin.tokenID
	if uid != "u1" || tokID != "tok-9" {
		t.Errorf("resolved (user=%q, token=%q), want (u1, tok-9)", uid, tokID)
	}
}

// An API-token bearer must resolve with an EMPTY session_token_id, so Logout
// (which revokes the session_token_id) refuses them with FailedPrecondition and
// revokes nothing. Otherwise it revokes the API TOKEN itself —
// RevokeSessionToken's DQL drops the token_type filter (the column is
// api_token-gated), so an id+user_id match revokes the API token by mistake, a
// credential that should only be revoked via RevokeApiToken.
func TestResolvePrincipalRealmAware_ApiTokenHasNoSessionID(t *testing.T) {
	m := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{StoredTokenHash: "stored", UserId: "u1", TokenId: "api-7", TokenType: pb.TokenType_TOKEN_TYPE_API},
		realmPerms: []int32{1, 2},
		subset:     []int32{1},
	}
	h := &AuthServiceHandler{Query: m}
	prin, err := resolvePrincipalRealmAware(context.Background(), h, "tok")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	uid, tokID := prin.userID, prin.tokenID
	if uid != "u1" {
		t.Errorf("user = %q, want u1", uid)
	}
	if tokID != "" {
		t.Errorf("API-token session_token_id = %q, want \"\" (Logout must refuse API tokens, not revoke them)", tokID)
	}
}
