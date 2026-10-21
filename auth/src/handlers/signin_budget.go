package handlers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// SignIn's guess budget — base tier, staged with every feature
// (sign-in/failure-budget).
//
// The gateway bounds guessing per client ADDRESS. That bounds nobody who
// spreads the guesses over many addresses, and behind a terminator whose
// address the gateway does not see through it becomes one bucket for
// everybody. This bounds them per ACCOUNT, independently of where they come
// from:
//
//   - every password attempt at an account is counted against it, BEFORE its
//     password is checked, in one statement (CountSignInAttempt): concurrent
//     guesses get distinct counts, so none of them shares a budget;
//   - once signInFailureBudget attempts are spent in the window, the account
//     is NOT locked. Only a device that has signed in to the account before
//     — a live, signed-in Device row of the proof's key, which only a client
//     that knew the password could have made — may still try, and each such
//     device has a budget of its own (CountDeviceSignInAttempt), so a stolen
//     device key is no unlimited oracle either;
//   - a correct password resets the account's budget and the device's
//     (ResetSignInAttempts).
//
// The trade-off, chosen over a lockout: a lockout would hand anyone who knows
// an address a way to keep its owner out. This keeps the owner in on every
// device they have used, and makes them wait out the window on a new one
// while someone is guessing.
//
// A refusal is the wrong-password refusal (same code, same message, and
// SignIn runs the throwaway verify so it takes as long): the budget must not
// tell a caller that an address has an account, or that it is under attack.

const (
	defaultSignInFailureBudget        = 20
	defaultSignInDeviceFailureBudget  = 10
	defaultSignInFailureWindowSeconds = 900
)

// errSignInThrottled is the cause of a refusal by the budget. Never
// surfaced (SignIn answers it as a wrong password); recorded in the history
// as THROTTLED.
var errSignInThrottled = errors.New("sign-in guess budget spent")

// signInBudgetApplies reports whether the handler's store keeps the budget.
// Always in production; a variable only so the package's tests can tell the
// stores that keep it from the fakes that predate it (see TestMain).
var signInBudgetApplies = func(*AuthServiceHandler) bool { return true }

func (h *AuthServiceHandler) signInFailureBudget() int64 {
	if h.SignInFailureBudget > 0 {
		return int64(h.SignInFailureBudget)
	}
	return defaultSignInFailureBudget
}

func (h *AuthServiceHandler) signInDeviceFailureBudget() int64 {
	if h.SignInDeviceFailureBudget > 0 {
		return int64(h.SignInDeviceFailureBudget)
	}
	return defaultSignInDeviceFailureBudget
}

func (h *AuthServiceHandler) signInFailureWindow() time.Duration {
	if h.SignInFailureWindowSeconds > 0 {
		return time.Duration(h.SignInFailureWindowSeconds) * time.Second
	}
	return defaultSignInFailureWindowSeconds * time.Second
}

// spendSignInBudget counts one password attempt at userID from the key
// thumbprint, and refuses it (errSignInThrottled) when the budget is spent.
// An attempt it could not count is refused too: an unaccounted guess is not
// granted.
func spendSignInBudget(ctx context.Context, h *AuthServiceHandler, userID, thumbprint string) error {
	if !signInBudgetApplies(h) {
		return nil
	}
	now := time.Now()
	cutoff := timestamppb.New(now.Add(-h.signInFailureWindow()))
	acct, err := h.Mutation.CountSignInAttempt(ctx, &pb.CountSignInAttemptReq{
		UserId: userID, Now: timestamppb.New(now), Cutoff: cutoff,
	})
	if err != nil {
		return err
	}
	if n := acct.GetAttempts(); n == 0 {
		return errSignInThrottled // no row counted: nothing to grant
	} else if n <= h.signInFailureBudget() {
		return nil
	}
	dev, err := h.Mutation.CountDeviceSignInAttempt(ctx, &pb.CountDeviceSignInAttemptReq{
		UserId: userID, Thumbprint: thumbprint, Now: timestamppb.New(now), Cutoff: cutoff,
	})
	if notFoundOK(err) != nil {
		return err
	}
	if n := dev.GetAttempts(); n == 0 || n > h.signInDeviceFailureBudget() {
		return errSignInThrottled
	}
	return nil
}

// resetSignInBudget starts the account's budget and the device's over after
// a correct password. A failed reset is logged and refuses nothing: the
// password was right, and the worst it costs is a budget that runs out
// sooner.
func resetSignInBudget(ctx context.Context, h *AuthServiceHandler, userID, thumbprint string) {
	if !signInBudgetApplies(h) {
		return
	}
	if _, err := h.Mutation.ResetSignInAttempts(ctx, &pb.ResetSignInAttemptsReq{UserId: userID, Thumbprint: thumbprint}); err != nil {
		slog.WarnContext(ctx, "auth: sign-in guess budget not reset", "user_id", userID, "err", err)
	}
}
