package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// apiTokenMgmtMock satisfies both client interfaces (embedded nil) and
// records what the management handlers called.
type apiTokenMgmtMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	issueReq       *pb.IssueApiTokenReq
	addedPerms     []int32
	deleteReq      *pb.DeleteApiTokenReq
	deletedTokenID string // what DeleteApiToken RETURNINGs (empty = nothing deleted)
	subsetCleared  bool
	listResult     []*pb.ApiTokenInfo
	// addPermErr fails the NARROWING — the second half of the pair, and the
	// failure the transaction exists for. A rollback here is what keeps a live
	// token from being left behind with no subset.
	addPermErr error
}

func (m *apiTokenMgmtMock) IssueApiToken(ctx context.Context, in *pb.IssueApiTokenReq, _ ...grpc.CallOption) (*pb.IssueApiTokenResp, error) {
	m.issueReq = in
	return &pb.IssueApiTokenResp{Token: &pb.UserToken{Id: "tok-1", Token: "secret-xyz"}}, nil
}
func (m *apiTokenMgmtMock) AddTokenPermission(ctx context.Context, in *pb.AddTokenPermissionReq, _ ...grpc.CallOption) (*pb.AddTokenPermissionResp, error) {
	if m.addPermErr != nil {
		return nil, m.addPermErr
	}
	m.addedPerms = append(m.addedPerms, in.GetPermissionId())
	return &pb.AddTokenPermissionResp{}, nil
}
func (m *apiTokenMgmtMock) DeleteApiToken(ctx context.Context, in *pb.DeleteApiTokenReq, _ ...grpc.CallOption) (*pb.DeleteApiTokenResp, error) {
	m.deleteReq = in
	return &pb.DeleteApiTokenResp{TokenId: m.deletedTokenID}, nil
}
func (m *apiTokenMgmtMock) DeleteTokenPermissions(ctx context.Context, in *pb.DeleteTokenPermissionsReq, _ ...grpc.CallOption) (*pb.DeleteTokenPermissionsResp, error) {
	m.subsetCleared = true
	return &pb.DeleteTokenPermissionsResp{}, nil
}
func (m *apiTokenMgmtMock) ListApiTokensByUser(ctx context.Context, in *pb.ListApiTokensByUserReq, _ ...grpc.CallOption) (*pb.ListApiTokensByUserResp, error) {
	return &pb.ListApiTokensByUserResp{Tokens: m.listResult}, nil
}

func ctxWithCaller(uid string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(scopeUserIDKey, uid))
}

func TestCreateApiToken_StampsAPIRealm_AndSubset(t *testing.T) {
	m := &apiTokenMgmtMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{Name: "ci", PermissionSubset: []int32{5, 7}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.GetToken() != "secret-xyz" || resp.GetTokenId() != "tok-1" {
		t.Errorf("resp = %+v, want token secret-xyz / id tok-1", resp)
	}
	if m.issueReq.GetUserId() != "u1" {
		t.Errorf("issue user_id = %q, want u1 (caller)", m.issueReq.GetUserId())
	}
	if m.issueReq.GetTokenType() != pb.TokenType_TOKEN_TYPE_API {
		t.Errorf("issue token_type = %v, want API (handler-stamped)", m.issueReq.GetTokenType())
	}
	if len(m.addedPerms) != 2 || m.addedPerms[0] != 5 || m.addedPerms[1] != 7 {
		t.Errorf("added perms = %v, want [5 7]", m.addedPerms)
	}
}

func TestCreateApiToken_NoCaller_Unauthenticated(t *testing.T) {
	h := &AuthServiceHandler{Query: &apiTokenMgmtMock{}, Mutation: &apiTokenMgmtMock{}}
	if _, err := h.CreateApiToken(context.Background(), &pb.CreateApiTokenReq{}); err == nil {
		t.Fatal("expected Unauthenticated without scope metadata")
	}
}

func TestRevokeApiToken_Owned_ClearsSubset(t *testing.T) {
	m := &apiTokenMgmtMock{deletedTokenID: "tok-1"} // token was deleted (owned)
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeApiToken(ctxWithCaller("u1"), &pb.RevokeApiTokenReq{TokenId: "tok-1"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if m.deleteReq.GetUserId() != "u1" || m.deleteReq.GetTokenType() != pb.TokenType_TOKEN_TYPE_API {
		t.Errorf("delete guard wrong: %+v", m.deleteReq)
	}
	if !m.subsetCleared {
		t.Error("owned-token revoke must clear the subset rows")
	}
}

func TestRevokeApiToken_NotOwned_SkipsSubsetCleanup(t *testing.T) {
	m := &apiTokenMgmtMock{deletedTokenID: ""} // nothing deleted (not owner / not API)
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeApiToken(ctxWithCaller("u1"), &pb.RevokeApiTokenReq{TokenId: "someone-elses"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if m.subsetCleared {
		t.Error("must NOT clear subset rows when no owned token was deleted")
	}
}

func TestListApiTokens_ReturnsCallersTokens(t *testing.T) {
	m := &apiTokenMgmtMock{listResult: []*pb.ApiTokenInfo{{Id: "tok-1", Name: "ci"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListApiTokens(ctxWithCaller("u1"), &pb.ListApiTokensReq{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetTokens()) != 1 || resp.GetTokens()[0].GetId() != "tok-1" {
		t.Errorf("tokens = %+v, want [tok-1]", resp.GetTokens())
	}
}

// --- revoke, when the token had no permission subset -------------------

type revokeMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	cleanupErr error
	cleanupRan bool
}

func (m *revokeMock) DeleteApiToken(ctx context.Context, in *pb.DeleteApiTokenReq, _ ...grpc.CallOption) (*pb.DeleteApiTokenResp, error) {
	return &pb.DeleteApiTokenResp{TokenId: in.GetTokenId()}, nil
}

func (m *revokeMock) DeleteTokenPermissions(ctx context.Context, _ *pb.DeleteTokenPermissionsReq, _ ...grpc.CallOption) (*pb.DeleteTokenPermissionsResp, error) {
	m.cleanupRan = true
	return &pb.DeleteTokenPermissionsResp{}, m.cleanupErr
}

// The common case: a token with no subset. The cleanup DELETE matches no row,
// which the generated mutation reports as NotFound — and the token is ALREADY
// deleted by then. Failing here told the caller "no such token" about a token
// that had just been revoked, and a retry said the same, so the operator
// concluded it was still live.
func TestRevokeApiToken_EmptySubsetIsNotAFailure(t *testing.T) {
	m := &revokeMock{cleanupErr: status.Error(codes.NotFound, "AuthMutation.DeleteTokenPermissions: not found")}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.RevokeApiToken(ctxWithCaller("u1"), &pb.RevokeApiTokenReq{TokenId: "tok-1"}); err != nil {
		t.Fatalf("revoking a token with no permission subset failed: %v", err)
	}
	if !m.cleanupRan {
		t.Error("the cleanup never ran — the test would pass for the wrong reason")
	}
}

// Control: only NotFound is swallowed. A subset that could not be removed
// leaves a credential narrower than it looks, and must still fail.
func TestRevokeApiToken_OtherCleanupErrorsStillFail(t *testing.T) {
	m := &revokeMock{cleanupErr: status.Error(codes.Unavailable, "db down")}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	if _, err := h.RevokeApiToken(ctxWithCaller("u1"), &pb.RevokeApiTokenReq{TokenId: "tok-1"}); err == nil {
		t.Fatal("a failed subset cleanup was reported as a successful revoke")
	}
}

// ── the CreateApiToken transaction ──────────────────────────────────────

func newApiTokenHandlerTx(m *apiTokenMgmtMock, tx *recordingDistTx) *AuthServiceHandler {
	return &AuthServiceHandler{Query: m, Mutation: m, DistTx: tx, Connection: "app-postgres"}
}

// The arm this exists for. Minting comes first because a permission row points
// at the token's id, so a failed narrowing leaves a LIVE token — and with an
// empty subset the resolver reads `all_permissions`. The caller gets an error
// and would be left owning a credential WIDER than the one they asked for.
//
// ⚠️ This endpoint was missed when the identical shape was fixed in
// IssueBotToken and CreateBot the same day. The bot endpoints are called by an
// admin; this one is called by everybody.
func TestCreateApiToken_NarrowingFails_RollsBackTheLiveToken(t *testing.T) {
	tx := &recordingDistTx{}
	m := &apiTokenMgmtMock{addPermErr: errTestNarrowFailed}
	h := newApiTokenHandlerTx(m, tx)

	_, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{
		Name: "ci", PermissionSubset: []int32{7},
	})
	if err == nil {
		t.Fatal("a failed narrowing must fail the mint — otherwise the caller owns a wider credential than they asked for")
	}
	if m.issueReq == nil {
		t.Fatal("this arm is not exercising the hole: no token was minted, so there is nothing to roll back")
	}
	if got := tx.settled(); got != "rolled back" {
		t.Fatalf("a failed narrowing left its transaction %s, want rolled back — a LIVE unnarrowed token is what stays behind", got)
	}
}

// The happy path commits, on the handler's own connection: a Begin elsewhere
// holds a transaction the two writes never join, so the rollback above would
// undo nothing.
func TestCreateApiToken_Success_CommitsOnTheHandlersConnection(t *testing.T) {
	tx := &recordingDistTx{}
	m := &apiTokenMgmtMock{}
	h := newApiTokenHandlerTx(m, tx)

	if _, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{
		Name: "ci", PermissionSubset: []int32{7, 9},
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got := tx.settled(); got != "committed" {
		t.Fatalf("a successful mint left its transaction %s, want committed", got)
	}
	if len(tx.begun) != 1 || tx.begun[0] != "app-postgres" {
		t.Errorf("Begin connections = %v, want exactly one on the handler's connection", tx.begun)
	}
	if len(m.addedPerms) != 2 {
		t.Errorf("narrowed permissions = %v, want both — the subset is the whole point of the credential", m.addedPerms)
	}
}

// A refused Begin must mint nothing: proceeding without a coordinator restores
// the pre-fix behaviour exactly when the coordinator is unhealthy.
func TestCreateApiToken_BeginRefused_MintsNothing(t *testing.T) {
	tx := &recordingDistTx{beginErr: errTestBeginRefused}
	m := &apiTokenMgmtMock{}
	h := newApiTokenHandlerTx(m, tx)

	if _, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{
		Name: "ci", PermissionSubset: []int32{7},
	}); err == nil {
		t.Fatal("a refused Begin must fail the mint")
	}
	if m.issueReq != nil {
		t.Error("a token was minted with no transaction to hold it together with its narrowing")
	}
}
