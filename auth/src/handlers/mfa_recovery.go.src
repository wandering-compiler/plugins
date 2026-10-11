package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file is the rest of the `two_factor` feature (staged with mfa.go,
// plugin.yaml go_files): a TOTP code accepted at most once, recovery codes,
// and the step-up every change to an authenticator asks for.

const (
	// recoveryCodeCount is the size of a set — the common number, enough for
	// a year of lost phones and short enough to write down.
	recoveryCodeCount = 10
	// recoveryCodeLen characters from recoveryAlphabet: 31^10 ≈ 2^49.5.
	// Against a guesser that is bounded by the challenge's attempt budget,
	// like the six digits it stands in for, and far beyond them.
	recoveryCodeLen = 10
	// No 0/o, 1/l/i: a code is read off paper and typed on a phone.
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

	// maxStepUpAttempts wrong step-up codes in a row lock it for stepUpLockout.
	maxStepUpAttempts = 5
	stepUpLockout     = 15 * time.Minute
)

// stepUpLocked refuses a step-up whose guess budget is spent. Deliberate and
// non-opaque, like errMfaChallengeBudget — only a signed-in session reaches it.
func stepUpLocked(ctx context.Context) error {
	return refusal(ctx, codes.ResourceExhausted, "two_factor: step-up locked after too many wrong codes",
		CodeStepUpLocked, "", MsgStepUpLocked, nil)
}

// acceptTotp reports whether code is the authenticator's current code AND
// claims its time step, so the same code — replayed, overheard, or sent twice
// at once — is accepted once. The claim is one conditional UPDATE: of two
// concurrent requests only one gets the row back. A claim the store does not
// answer is an error, never an acceptance.
func (h *AuthServiceHandler) acceptTotp(ctx context.Context, row *pb.UserTotpSecret, seed, code string) (bool, error) {
	step, ok := totp.Match(seed, code, time.Now(), totpSkewSteps)
	if !ok {
		return false, nil
	}
	claimed, err := h.Mutation.ClaimTotpStep(ctx, &pb.ClaimTotpStepReq{Id: row.GetId(), Step: step})
	if err != nil {
		if notFoundOK(err) == nil {
			return false, nil // nothing matched: a step already used
		}
		return false, err
	}
	return claimed.GetId() != "", nil
}

// acceptRecoveryCode spends one of the user's recovery codes. Anything that
// is not shaped like one is refused without a lookup.
func (h *AuthServiceHandler) acceptRecoveryCode(ctx context.Context, userID, code string) bool {
	norm := normaliseRecoveryCode(code)
	if len(norm) != recoveryCodeLen {
		return false
	}
	spent, err := h.Mutation.ConsumeRecoveryCode(ctx, &pb.ConsumeRecoveryCodeReq{UserId: userID, CodeHash: recoveryCodeHash(norm)})
	return err == nil && spent.GetId() != ""
}

// stepUp is the proof a change to a CONFIRMED authenticator asks for: a
// current code from it, or a recovery code. A session alone is not enough —
// a stolen one would otherwise be able to remove or replace the factor that
// limits what it can do.
//
// Budgeted: maxStepUpAttempts wrong codes lock it for stepUpLockout. A
// sign-in's guesses are bounded by its challenge; these calls come from a
// session, and without a budget of their own a stolen one could try codes
// until one of the three a ±1 skew accepts came up.
//
// A recovery-shaped code is checked as one without touching the seed, so a
// legacy authenticator whose old key is gone can still be replaced with a
// recovery code — the case they exist for.
func (h *AuthServiceHandler) stepUp(ctx context.Context, userID string, row *pb.UserTotpSecret, code string) error {
	att, err := h.Mutation.RecordStepUpAttempt(ctx, &pb.RecordStepUpAttemptReq{Id: row.GetId()})
	if err != nil && notFoundOK(err) != nil {
		return Unauthenticated(errMfaChallengeInvalid) // an unaccounted guess is not granted
	}
	if att.GetAttempts() == 0 {
		return stepUpLocked(ctx)
	}
	if att.GetAttempts() > maxStepUpAttempts {
		_, _ = h.Mutation.LockStepUp(ctx, &pb.LockStepUpReq{Id: row.GetId(), Until: timestamppb.New(time.Now().Add(stepUpLockout))})
		return stepUpLocked(ctx)
	}
	var ok bool
	if len(normaliseRecoveryCode(code)) == recoveryCodeLen {
		ok = h.acceptRecoveryCode(ctx, userID, code)
	} else {
		seed, err := h.seedOf(ctx, row)
		if err != nil {
			return err
		}
		if ok, err = h.acceptTotp(ctx, row, seed, code); err != nil {
			return err
		}
	}
	if !ok {
		return Unauthenticated(errMfaChallengeInvalid)
	}
	_, _ = h.Mutation.ResetStepUp(ctx, &pb.ResetStepUpReq{Id: row.GetId()})
	return nil
}

// GenerateRecoveryCodes replaces the caller's recovery codes with a fresh set,
// returned once. Needs a confirmed authenticator and the step-up.
func (h *AuthServiceHandler) GenerateRecoveryCodes(ctx context.Context, req *pb.GenerateRecoveryCodesReq) (*pb.GenerateRecoveryCodesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	enrolled, row, err := h.totpEnrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enrolled || !h.TwoFactorTOTP {
		return nil, refusal(ctx, codes.FailedPrecondition, "two_factor: recovery codes need a confirmed authenticator",
			CodeTotpNotEnrolled, "", MsgTotpNotEnrolled, nil)
	}
	if err := h.stepUp(ctx, userID, row, req.GetCode()); err != nil {
		return nil, err
	}
	var out []string
	if err := h.inMfaTx(ctx, func(txCtx context.Context) error {
		var err error
		out, err = h.replaceRecoveryCodes(txCtx, userID)
		return err
	}); err != nil {
		return nil, err
	}
	return &pb.GenerateRecoveryCodesResp{RecoveryCodes: out}, nil
}

// replaceRecoveryCodes deletes the user's set and stores a fresh one,
// returning the plaintext (formatted xxxxx-xxxxx). Run it inside a
// transaction: half a set is a set the person believes they have.
func (h *AuthServiceHandler) replaceRecoveryCodes(txCtx context.Context, userID string) ([]string, error) {
	if _, err := h.Mutation.DeleteRecoveryCodes(txCtx, &pb.DeleteRecoveryCodesReq{UserId: userID}); notFoundOK(err) != nil {
		return nil, err
	}
	out := make([]string, 0, recoveryCodeCount)
	for len(out) < recoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		if _, err := h.Mutation.CreateRecoveryCode(txCtx, &pb.CreateRecoveryCodeReq{UserId: userID, CodeHash: recoveryCodeHash(code)}); err != nil {
			return nil, err
		}
		out = append(out, code[:recoveryCodeLen/2]+"-"+code[recoveryCodeLen/2:])
	}
	return out, nil
}

func newRecoveryCode() (string, error) {
	max := big.NewInt(int64(len(recoveryAlphabet)))
	b := make([]byte, recoveryCodeLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = recoveryAlphabet[n.Int64()]
	}
	return string(b), nil
}

// normaliseRecoveryCode accepts what a person types: any case, the dash or
// not, stray spaces.
func normaliseRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(code)))
}

func recoveryCodeHash(norm string) string {
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
