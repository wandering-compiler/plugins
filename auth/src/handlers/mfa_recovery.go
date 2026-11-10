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

	"github.com/wandering-compiler/plugins/auth/lib/passwordhash"
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
//
// The code is looked up as its slow hash (recoveryCodeHash) and, when that
// spends nothing, as the SHA-256 a set made before the slow hash was stored
// with (legacyRecoveryCodeHash): such a set keeps working, each code once,
// until it is used up or replaced — no row is rewritten. Each lookup is the
// one conditional UPDATE that spends the code, so single use still holds.
func (h *AuthServiceHandler) acceptRecoveryCode(ctx context.Context, userID, code string) bool {
	norm := normaliseRecoveryCode(code)
	if len(norm) != recoveryCodeLen {
		return false
	}
	for _, hash := range []string{recoveryCodeHash(userID, norm), legacyRecoveryCodeHash(norm)} {
		spent, err := h.Mutation.ConsumeRecoveryCode(ctx, &pb.ConsumeRecoveryCodeReq{UserId: userID, CodeHash: hash, Thumbprint: requestThumbprint(ctx)})
		if err == nil && spent.GetId() != "" {
			return true
		}
	}
	return false
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
		// An unaccounted guess is not granted. An outage is said as one
		// (AUTH_UNAVAILABLE), so the person retries instead of retyping.
		if operationalCode(err) != codes.OK {
			return Unauthenticated(err)
		}
		return UnauthenticatedMfaCode(errMfaChallengeInvalid)
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
		return UnauthenticatedMfaCode(errMfaChallengeInvalid)
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
	// Recovery codes stand in for the second factor — see EnrollTotp.
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
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
	if err := h.inTx(ctx, func(txCtx context.Context) error {
		var err error
		out, err = h.replaceRecoveryCodes(txCtx, userID)
		return err
	}); err != nil {
		return nil, err
	}
	return &pb.GenerateRecoveryCodesResp{RecoveryCodes: out}, nil
}

// replaceRecoveryCodes revokes the user's unused codes and stores a fresh set,
// returning the plaintext (formatted xxxxx-xxxxx). Run it inside a
// transaction: half a set is a set the person believes they have.
func (h *AuthServiceHandler) replaceRecoveryCodes(txCtx context.Context, userID string) ([]string, error) {
	if _, err := h.Mutation.RevokeRecoveryCodes(txCtx, &pb.RevokeRecoveryCodesReq{UserId: userID}); notFoundOK(err) != nil {
		return nil, err
	}
	out := make([]string, 0, recoveryCodeCount)
	for len(out) < recoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		if _, err := h.Mutation.CreateRecoveryCode(txCtx, &pb.CreateRecoveryCodeReq{UserId: userID, CodeHash: recoveryCodeHash(userID, code)}); err != nil {
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

// recoveryCodeHash is what a recovery code is stored and looked up as:
// argon2id of the normalised code, salted by the account, with parameters
// fixed in code (passwordhash.FixedArgon2idHex), not the deployment's
// password parameters, because the value is recomputed at every attempt.
//
// A code is ~2^49.5 and lives until it is used — the longest-lived of the
// plugin's low-entropy secrets — so a plain digest of it falls to an offline
// search from any read of the table (a backup, a replica) in hours. Here
// every guess costs an argon2id derivation, and the salt makes it a guess
// against ONE account. The salt is derived from the user id rather than
// random so the hash stays deterministic: the code is still spent by the one
// conditional UPDATE keyed on it (single use under concurrency), with no
// read-then-verify of the account's rows. It is not secret, and need not be.
func recoveryCodeHash(userID, norm string) string {
	salt := sha256.Sum256([]byte("w17-auth-recovery-code\x00" + userID))
	return passwordhash.FixedArgon2idHex(norm, salt[:16])
}

// legacyRecoveryCodeHash is how sets made before recoveryCodeHash were
// stored: the plain SHA-256 of the normalised code. Only ever looked up,
// never written.
func legacyRecoveryCodeHash(norm string) string {
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
