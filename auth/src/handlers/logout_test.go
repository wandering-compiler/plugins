package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// Q51-auth-2 — base-tier logout (no `devices` feature): revoke the
// caller's CURRENT session token, identified by the session_token_id
// Authenticate threads in the auth envelope (never the raw bearer).

type logoutMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	deleteReq *pb.DeleteSessionTokenReq
	deleteErr error
}

func (m *logoutMock) DeleteSessionToken(_ context.Context, in *pb.DeleteSessionTokenReq, _ ...grpc.CallOption) (*pb.DeleteSessionTokenResp, error) {
	m.deleteReq = in
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return &pb.DeleteSessionTokenResp{TokenId: in.GetTokenId(), UserId: in.GetUserId()}, nil
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
	if m.deleteReq == nil {
		t.Fatal("Logout did not call DeleteSessionToken")
	}
	if m.deleteReq.GetTokenId() != "tok-1" || m.deleteReq.GetUserId() != "u1" {
		t.Errorf("delete guard wrong: %+v (want token tok-1 / user u1)", m.deleteReq)
	}
	if m.deleteReq.GetTokenType() != pb.TokenType_TOKEN_TYPE_SESSION {
		t.Errorf("delete token_type = %v, want SESSION (logout must never revoke an API token)", m.deleteReq.GetTokenType())
	}
}

// No session_token_id in the envelope (e.g. an API-token bearer, or a
// direct gRPC call) → idempotent no-op, never deletes anything.
func TestLogout_NoSessionToken_NoOp(t *testing.T) {
	m := &logoutMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(ctxWithEnvelope(t, "u1", ""), &pb.LogoutReq{}); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if m.deleteReq != nil {
		t.Errorf("must not delete when there is no session token id; got %+v", m.deleteReq)
	}
}

// Deleting an already-revoked / expired token (zero rows → NotFound) is an
// idempotent logout success.
func TestLogout_AlreadyRevoked_Idempotent(t *testing.T) {
	m := &logoutMock{deleteErr: status.Error(codes.NotFound, "no rows")}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.Logout(ctxWithEnvelope(t, "u1", "tok-1"), &pb.LogoutReq{}); err != nil {
		t.Fatalf("logout of an already-revoked session must succeed, got %v", err)
	}
}

// A real (non-NotFound) mutation error must propagate, not be swallowed.
func TestLogout_MutationError_Propagates(t *testing.T) {
	m := &logoutMock{deleteErr: errors.New("db down")}
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
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "tok-9", TokenType: pb.TokenType_TOKEN_TYPE_SESSION},
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

// B21-auth-1: an API-token bearer must resolve with an EMPTY session_token_id,
// so Logout (which deletes the session_token_id) NO-OPs for them. Otherwise it
// deletes the API TOKEN itself — DeleteSessionToken's DQL drops the token_type
// filter (Q64-auth-1), so an id+user_id match revokes the API token by mistake,
// a credential that should only be removed via RevokeApiToken. The Logout
// docstring already promises an API-token bearer "still gets a clean success".
func TestResolvePrincipalRealmAware_ApiTokenHasNoSessionID(t *testing.T) {
	m := &apiTokenQueryMock{
		tok:        &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "api-7", TokenType: pb.TokenType_TOKEN_TYPE_API},
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
		t.Errorf("API-token session_token_id = %q, want \"\" (Logout must no-op for API tokens, not revoke them)", tokID)
	}
}
