package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
)

// This file implements the `sign_up_turnkey` feature. It is staged into a
// bundle ONLY when the activation enables sign_up_turnkey (plugin.yaml
// go_files). With the feature off — e.g. an admin auth activation that
// seeds accounts instead of self-registration — it is not staged, so the
// SignUp RPC and its request/response types (gated by the same feature)
// vanish together: no dangling reference to pb.SignUpReq from an always-
// compiled file. Standalone (the plugin author's own go test) always
// compiles it, since gating happens at activation staging.

// signupCreateUser creates the user during SignUp and returns its id.
// The default below is the plain create; handlers/tenant.go overrides it
// in init() when `tenant_scope` is staged, to resolve the request's
// tenant first and stamp it on the same call.
//
// The body used to live in its own file, signup_tenantless.go, staged
// only when the feature was OFF. That was forced: `tenant_scope` REMOVED
// the baseline CreateUser rpc (the feature adds a NOT NULL
// User.tenant_id that the fixed INSERT could not write), so a default
// referencing it would not compile in a tenant-scoped bundle — the
// override ran, but the dead code it replaced still had to compile.
//
// CreateUser now writes the column through a feature-gated SET
// assignment, so it survives every activation and the default can come
// home. Package-level var initialisation runs before any init(), so
// tenant.go's assignment still wins where it is staged.
//
// tenant_scope without sign_up_turnkey stays unsupported: tenant.go's
// override references this seam, which lives here under
// sign_up_turnkey.
var signupCreateUser = func(ctx context.Context, h *AuthServiceHandler, _ *pb.SignUpReq, email, passwordHash string) (string, error) {
	resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return "", err
	}
	return resp.GetUser().GetId(), nil
}

// SignUp is the canonical register-and-issue-token flow, made ATOMIC via the
// distributed transaction:
//
//  1. PasswordHash.Hash converts the plain password into the PHC-encoded hash
//     CreateUser persists (CPU-bound; deliberately OUTSIDE the tx).
//  2. signupResolveRoleIDs reads the turnkey role set from COMMITTED state —
//     first_user roles when no user exists yet, else default roles. Before the
//     tx, because query servers read the pool, not the tx.
//  3. Inside ONE distributed transaction (distx.Begin → the storage mutations
//     adopt the threaded w17-tx-id): signupCreateUser inserts the User,
//     signupAssignRoleIDs links its roles, IssueToken mints the bearer — then
//     Commit. Any failure rolls the whole thing back, so a signup never leaves
//     an orphan user without a role. Duplicate email surfaces as AlreadyExists.
//
// The invite gate it calls first lives in auth_service.go, because a
// second surface creates accounts too — see signupInviteGate.
func (h *AuthServiceHandler) SignUp(ctx context.Context, req *pb.SignUpReq) (*pb.SignUpResp, error) {
	// BEFORE the hash, and before any write. Argon2id is deliberately
	// expensive, so hashing first would let an uninvited caller spend the
	// server's CPU on every attempt — and a refusal that costs the
	// attacker nothing and the server plenty is a way in of its own.
	if err := signupInviteGate(ctx, h, normalizeEmail(req.GetEmail())); err != nil {
		return nil, err
	}

	hashed, err := h.PasswordHash.Hash(req.GetPassword())
	if err != nil {
		return nil, err
	}

	// Role decision from committed state, before the tx (see
	// resolveSignupRoleIDs). No-op unless the `rbac` feature is staged.
	roleIDs, err := signupResolveRoleIDs(ctx, h)
	if err != nil {
		return nil, err
	}

	// One transaction for the writes. No coordinator (a hand-built test
	// handler) → sequential calls, each its own tx — acceptable for a unit
	// test that doesn't exercise atomicity.
	txCtx := ctx
	var tx *distx.TxHandle
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}

	resp, err := h.signUpTx(txCtx, req, hashed, roleIDs)
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// signUpTx runs SignUp's write side against txCtx (carrying the distx w17-tx-id
// when a transaction is open): create the user, link its turnkey roles, mint
// the session token. Every storage call uses txCtx so all three join the one
// transaction.
func (h *AuthServiceHandler) signUpTx(txCtx context.Context, req *pb.SignUpReq, hashed string, roleIDs []string) (*pb.SignUpResp, error) {
	if signupCreateUser == nil {
		// Neither create path staged — see the seam's declaration. This
		// is a bundle-composition fault, not something a caller did, so
		// it says which knob is wrong instead of panicking on a nil call.
		return nil, status.Error(codes.Internal, "auth: no user-create path staged for this activation (sign_up_turnkey is on but neither the tenant-less nor the tenant_scope create was staged)")
	}
	userID, err := signupCreateUser(txCtx, h, req, normalizeEmail(req.GetEmail()), hashed)
	if err != nil {
		return nil, err
	}
	if err := signupAssignRoleIDs(txCtx, h, userID, roleIDs); err != nil {
		return nil, err
	}
	// Stamp the absolute session TTL like SignIn (issueSession): a SignUp-minted
	// bearer expires too. Without ExpiresAt the storage binds the proto zero
	// time (0001-01-01), which the validation guard reads as already-expired →
	// the fresh token 401s.
	tokResp, err := h.Mutation.IssueToken(txCtx, &pb.IssueTokenReq{UserId: userID, ExpiresAt: h.sessionTokenExpiry()})
	if err != nil {
		return nil, err
	}
	return &pb.SignUpResp{
		UserId: userID,
		Token:  tokResp.GetToken().GetToken(),
	}, nil
}
