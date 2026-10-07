package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
)

// This file implements `sign_up_confirmation`: SignUp proves the address
// before the account exists. Staged only with that feature (plugin.yaml
// go_files), which requires `sign_up_turnkey`, so pb.SignUpReq is always here
// when this file is. handlers/signup_confirm_tenant.go adds the tenant half
// when `tenant_scope` is staged too.
//
// Why a pending row and not an unverified User: a User row HOLDS its address
// — the email is unique — so an account created before the address is proved
// lets anybody who knows the address block it, simply by starting a
// registration and never finishing it. A PendingSignUp holds nothing. Any
// number may exist for one address, none of them can sign in, and the first
// one confirmed becomes the account.

const (
	// The code is the whole bound on guessing, and there is deliberately no
	// per-address cap beside it.
	//
	// A cap on how many codes one address may be sent is a lever anybody can
	// pull: send that many registrations and the owner's own request is
	// refused — the address blocked again, renewably, which is the thing this
	// feature exists to prevent (review of #221). Floods are bounded per
	// CALLER instead, by the gateway's limiter on unauthenticated methods.
	//
	// So the space carries it: eight characters of Crockford base32 (32^8 ≈
	// 1.1·10^12) against five attempts per pending row is ~2·10^11 rows — each
	// one a mail to the address — for an even chance. Eight DIGITS (10^8) would
	// be 10^7 rows, which a patient attacker spread across addresses can reach.
	signUpCodeLength = 8
	// Wrong codes one pending registration absorbs before it is dead.
	maxSignUpConfirmAttempts = 5

	defaultSignUpConfirmationTTL = 15 * time.Minute
)

// signUpCodeAlphabet is Crockford base32: no I, L, O or U, so nothing a person
// reads off a mail is ambiguous, and normalizeSignUpCode maps the look-alikes.
const signUpCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// generateSignUpCode returns signUpCodeLength characters of signUpCodeAlphabet
// from crypto/rand. 256 is a multiple of 32, so taking a byte modulo 32 is
// uniform.
func generateSignUpCode() (string, error) {
	buf := make([]byte, signUpCodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate sign-up code: %w", err)
	}
	for i, b := range buf {
		buf[i] = signUpCodeAlphabet[b%32]
	}
	return string(buf), nil
}

// normalizeSignUpCode turns what a person typed into the stored form: upper
// case, separators dropped, and Crockford's look-alikes mapped (O→0, I and
// L→1), so `abcd-efgh` and `ABCDEFGH` are the same code.
func normalizeSignUpCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case ' ', '-', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// errSignUpConfirmInvalid is every refusal of a confirmation: wrong code, a
// spent or expired registration, an unknown id. One answer, so a guesser
// learns nothing about which it was.
var errSignUpConfirmInvalid = status.Error(codes.InvalidArgument,
	"the confirmation code is wrong or has expired — register again to get a new one")

// The address already has an account: emailTaken (errors.go). Said by
// ConfirmSignUp only — to whoever holds the code mailed to that address, i.e.
// its owner — never by SignUp under this feature, whose answer must not tell a
// stranger which addresses are registered.

func init() {
	signUpConfirmation = startSignUpConfirmation
}

// pendingSignUpTenant stamps the tenant SignUp resolved on the pending row.
// A no-op without `tenant_scope`; handlers/signup_confirm_tenant.go replaces
// it, because the field it sets exists only with both features.
var pendingSignUpTenant = func(_ context.Context, _ *AuthServiceHandler, _ *pb.SignUpReq, _ *pb.CreatePendingSignUpReq) error {
	return nil
}

// confirmCreateUser creates the account from a claimed registration. The
// tenant-less create here; handlers/signup_confirm_tenant.go replaces it with
// one that writes the tenant the registration carried.
var confirmCreateUser = func(ctx context.Context, h *AuthServiceHandler, claimed *pb.ClaimPendingSignUpResp) (string, error) {
	resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{
		Email:        claimed.GetEmail(),
		PasswordHash: claimed.GetPasswordHash(),
	})
	if err != nil {
		return "", err
	}
	return resp.GetUser().GetId(), nil
}

func (h *AuthServiceHandler) signUpConfirmationTTL() time.Duration {
	if h.SignUpConfirmationTTLSeconds <= 0 {
		return defaultSignUpConfirmationTTL
	}
	return time.Duration(h.SignUpConfirmationTTLSeconds) * time.Second
}

// startSignUpConfirmation is SignUp under `sign_up_confirmation`. SignUp has
// already run the allowlist and invite gates.
//
// It does NOT look the address up. A registration for an address that already
// has an account goes exactly the way a new one does — same work, same answer,
// a code mailed to the address — and only ConfirmSignUp, which needs that
// code, says the account exists. Answering "taken" here told anybody which
// addresses have accounts (the request that asked for this flow named it:
// "the answer for an existing address must not differ from a new one"); the
// code reaches only the address's owner, so only they learn it, and they are
// the one person it is not news to.
func startSignUpConfirmation(ctx context.Context, h *AuthServiceHandler, req *pb.SignUpReq) (*pb.SignUpResp, error) {
	email := normalizeEmail(req.GetEmail())

	hashed, err := h.PasswordHash.Hash(req.GetPassword())
	if err != nil {
		return nil, err
	}
	code, err := generateSignUpCode()
	if err != nil {
		return nil, err
	}
	codeHash, err := h.PasswordHash.Hash(code)
	if err != nil {
		return nil, err
	}

	// Housekeeping for this address only: expired rows are dead anyway (every
	// read filters on expires_at), this keeps them from piling up.
	if _, err := h.Mutation.PurgeExpiredPendingSignUps(ctx, &pb.PurgeExpiredPendingSignUpsReq{Email: email}); err != nil {
		return nil, err
	}

	// The link is claimed when the registration STARTS, because only this call
	// carries it — the confirmation does not. An address that never confirms
	// keeps the invitation bound to itself, which is what an invitation
	// addressed to it would have been.
	//
	// The claim and the pending registration are one unit of work: a pending
	// row that fails to write must leave the link open (and a lost claim must
	// leave no pending row to confirm).
	txCtx := ctx
	var tx *distx.TxHandle
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	fail := func(err error) (*pb.SignUpResp, error) {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	if err := signupClaimInvite(txCtx, h, email, req.GetInviteToken()); err != nil {
		return fail(err)
	}

	create := &pb.CreatePendingSignUpReq{
		Email:        email,
		PasswordHash: hashed,
		CodeHash:     codeHash,
		ExpiresAt:    timestamppb.New(time.Now().Add(h.signUpConfirmationTTL())),
		Code:         code,
	}
	if err := pendingSignUpTenant(txCtx, h, req, create); err != nil {
		return fail(err)
	}
	created, err := h.Mutation.CreatePendingSignUp(txCtx, create)
	if err != nil {
		return fail(err)
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return &pb.SignUpResp{
		ConfirmationRequired: true,
		PendingId:            created.GetPending().GetId(),
	}, nil
}

// ConfirmSignUp turns a pending registration into the account once the code
// mailed to its address comes back.
//
//  1. RecordPendingSignUpAttempt claims one guess in the statement that counts
//     it (concurrent guesses cannot share a budget) and returns the hash to
//     check against. A zero count is no live row.
//  2. The code is checked, and the allowlist again — on the stored address,
//     because the list may have changed since the code was sent.
//  3. One transaction: claim the row (DELETE … RETURNING — two confirmations
//     racing get one account), create the User, link its roles, record the
//     proved address, delete the address's other pending registrations, mint
//     the session. An address registered meanwhile fails CreateUser's unique
//     constraint and rolls the claim back.
func (h *AuthServiceHandler) ConfirmSignUp(ctx context.Context, req *pb.ConfirmSignUpReq) (*pb.ConfirmSignUpResp, error) {
	att, err := h.Mutation.RecordPendingSignUpAttempt(ctx, &pb.RecordPendingSignUpAttemptReq{PendingId: req.GetPendingId()})
	if err != nil {
		// Fail closed: an attempt that could not be counted is not granted.
		return nil, errSignUpConfirmInvalid
	}
	if att.GetAttempts() == 0 || att.GetAttempts() > maxSignUpConfirmAttempts {
		return nil, errSignUpConfirmInvalid
	}
	if ok, _, _ := h.PasswordHash.VerifyAndRotate(att.GetCodeHash(), normalizeSignUpCode(req.GetCode()), nil); !ok {
		return nil, errSignUpConfirmInvalid
	}
	if err := signUpAllowlistGate(h, att.GetEmail()); err != nil {
		return nil, err
	}

	// Committed state, before the tx — the same reason SignUp reads it there.
	roleIDs, err := signupResolveRoleIDs(ctx, h)
	if err != nil {
		return nil, err
	}

	txCtx := ctx
	var tx *distx.TxHandle
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	resp, err := h.confirmSignUpTx(txCtx, req.GetPendingId(), roleIDs)
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

func (h *AuthServiceHandler) confirmSignUpTx(txCtx context.Context, pendingID string, roleIDs []string) (*pb.ConfirmSignUpResp, error) {
	claimed, err := h.Mutation.ClaimPendingSignUp(txCtx, &pb.ClaimPendingSignUpReq{PendingId: pendingID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, errSignUpConfirmInvalid
		}
		return nil, err
	}
	if claimed.GetEmail() == "" {
		// Claimed by a concurrent confirmation between the check and here.
		return nil, errSignUpConfirmInvalid
	}
	userID, err := confirmCreateUser(txCtx, h, claimed)
	if err != nil {
		if isEmailTaken(err) {
			return nil, emailTaken(txCtx)
		}
		return nil, err
	}
	if err := signupAssignRoleIDs(txCtx, h, userID, roleIDs); err != nil {
		return nil, err
	}
	if err := markEmailConfirmed(txCtx, h, userID); err != nil {
		return nil, err
	}
	if _, err := h.Mutation.DeletePendingSignUpsForEmail(txCtx, &pb.DeletePendingSignUpsForEmailReq{Email: claimed.GetEmail()}); err != nil {
		return nil, err
	}
	tokResp, err := h.Mutation.IssueToken(txCtx, &pb.IssueTokenReq{UserId: userID, ExpiresAt: h.sessionTokenExpiry()})
	if err != nil {
		return nil, err
	}
	return &pb.ConfirmSignUpResp{
		UserId: userID,
		Token:  tokResp.GetToken().GetToken(),
	}, nil
}
