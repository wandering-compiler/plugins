package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// sessionCallerCtx is a caller as the gateway hands it to a handler: the
// user_id scope plus the x-w17-user envelope Authenticate stamped. An empty
// sessionTokenID is an API-token caller, which Authenticate leaves without one.
func sessionCallerCtx(uid, sessionTokenID string) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: sessionTokenID, PermissionIds: []int32{5}})
	if err != nil {
		panic(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid,
		userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// An API token limited to one permission must not mint a token: the new one is
// built from the holder's roles, so it would carry every API-realm permission
// the holder has. Nothing may be written either.
func TestCreateApiToken_AnAPITokenCallerIsRefused(t *testing.T) {
	m := &apiTokenMgmtMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CreateApiToken(sessionCallerCtx("u1", ""), &pb.CreateApiTokenReq{PublicKey: p256JWK, Name: "wider"})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeSessionRequired {
		t.Fatalf("an API-token caller minted a token: err = %v, want PermissionDenied/%s", err, CodeSessionRequired)
	}
	if m.issueReq != nil {
		t.Errorf("a refused mint still wrote a token: %+v", m.issueReq)
	}
}

// The CLI exchange mints a full session, so an API token must not start it.
func TestCliAuthorize_AnAPITokenCallerIsRefused(t *testing.T) {
	m := &cliMock{codes: map[string]*cliCode{}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CliAuthorize(sessionCallerCtx("u1", ""), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(validVerifier()),
		RedirectUri:   "http://127.0.0.1:1/cb",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller started a CLI login: err = %v, want PermissionDenied", err)
	}
	if len(m.codes) != 0 {
		t.Errorf("a refused authorization still stored a code: %d stored", len(m.codes))
	}
}

// A trusted callback and its client secret are what CliAuthorize sends a
// session's code to; registering or restoring one is an operator's act with a
// session, never a token's.
func TestClientRegistry_AnAPITokenCallerIsRefused(t *testing.T) {
	m := newCliMock()
	m.registered = map[[2]string]bool{}
	h := newCliHandler(m)
	ctx := sessionCallerCtx("admin", "")
	_, err := h.RegisterClient(ctx, &pb.RegisterClientReq{ClientId: "c", RedirectUri: "https://evil.example/cb"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller registered a callback: err = %v, want PermissionDenied", err)
	}
	if len(m.registered) != 0 {
		t.Errorf("a refused registration still wrote a client: %v", m.registered)
	}
	// The mock does not implement SetAuthClientEnabled: reaching it panics.
	if _, err := h.SetClientEnabled(ctx, &pb.SetClientEnabledReq{Id: "row", Enabled: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller restored a callback: err = %v, want PermissionDenied", err)
	}
}

// An authenticator secret and its recovery codes are the account's second
// factor. An API token that could create them would own it.
func TestSecondFactor_AnAPITokenCallerIsRefused(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := sessionCallerCtx("u1", "")
	if _, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller enrolled an authenticator: err = %v, want PermissionDenied", err)
	}
	if m.totpSeed != "" || m.totpSecretEnc != "" {
		t.Error("a refused enrolment still stored a secret")
	}
	if _, err := h.GenerateRecoveryCodes(ctx, &pb.GenerateRecoveryCodesReq{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an API-token caller generated recovery codes: err = %v, want PermissionDenied", err)
	}
}

// requireSessionCaller trusts Authenticate's session_token_id, so the
// resolver is where the guard actually holds: a SESSION token is stamped,
// every other type is not — including one with no type, which must fail
// closed rather than pass as a session.
func TestResolvePrincipalRealmAware_OnlyASessionCarriesItsTokenID(t *testing.T) {
	for _, tc := range []struct {
		typ  pb.TokenType
		want string
	}{
		{pb.TokenType_TOKEN_TYPE_SESSION, "t1"},
		{pb.TokenType_TOKEN_TYPE_API, ""},
		{pb.TokenType_TOKEN_TYPE_UNSPECIFIED, ""},
	} {
		mock := &apiTokenQueryMock{
			tok:        &pb.GetTokenWithTypeResp{StoredTokenHash: "stored", UserId: "u1", TokenId: "t1", TokenType: tc.typ},
			realmPerms: []int32{1},
		}
		prin, err := resolvePrincipalRealmAware(context.Background(), &AuthServiceHandler{Query: mock}, "tok")
		if err != nil {
			t.Fatalf("%v: resolve: %v", tc.typ, err)
		}
		if prin.tokenID != tc.want {
			t.Errorf("%v: tokenID = %q, want %q", tc.typ, prin.tokenID, tc.want)
		}
	}
}
