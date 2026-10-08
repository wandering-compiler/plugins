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
)

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
func (h *AuthServiceHandler) stepUp(ctx context.Context, userID string, row *pb.UserTotpSecret, code string) error {
	seed, err := h.seedOf(ctx, row)
	if err != nil {
		return err
	}
	ok, err := h.acceptTotp(ctx, row, seed, code)
	if err != nil {
		return err
	}
	if !ok && !h.acceptRecoveryCode(ctx, userID, code) {
		return Unauthenticated(errMfaChallengeInvalid)
	}
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
