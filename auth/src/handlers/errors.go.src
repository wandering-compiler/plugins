package handlers

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// authnError is the opaque error every auth-handler failure
// path returns. It carries an optional cause for handler-side
// logging via errors.Unwrap; the cause never reaches the wire.
//
// GRPCStatus is the integration point the gRPC server uses to
// map an error onto a wire status. The value is fixed —
// codes.Unauthenticated + "invalid credentials" — regardless
// of cause, which is what enforces anti-enumeration: an
// attacker probing the auth handler observes the same wire
// response for "no such email", "wrong password", "DB
// transient failure", and so on.
type authnError struct {
	cause error
}

const authnErrorMessage = "invalid credentials"

// Error returns the opaque message — never the cause. Handlers
// that want the cause exposed for logging should call
// errors.Unwrap or use slog's structured fields with both the
// returned error AND the unwrapped cause.
func (e *authnError) Error() string {
	return authnErrorMessage
}

// GRPCStatus is the hook google.golang.org/grpc/status.FromError looks for to
// construct the wire status.
//
// Every REFUSAL gets the same opaque answer — that is the anti-enumeration
// contract and it is unchanged. What is no longer folded in with them is an
// OUTAGE.
//
// This used to be fixed "regardless of cause", and the comment listed what it
// collapsed: "no such email", "wrong password", "DB transient failure". The
// first two belong together; the third is not a refusal at all. A consumer
// built a facade that wanted to tell an outage from a rejection and could not,
// because the information was destroyed here — so their running service, with
// its database down, told people their password was wrong. That is a lie they
// cannot check, and it sends them to reset a password that was fine (marb,
// 2026-09-23).
//
// Nothing leaks: the operational answer is the same for every caller and every
// address, so "the service is degraded" says nothing about whether an account
// exists. The classification is on the CAUSE's own status code, and only codes
// that describe the service rather than the credential flip.
func (e *authnError) GRPCStatus() *status.Status {
	if c := operationalCode(e.cause); c != codes.OK {
		return status.New(c, "the authentication service is temporarily unavailable")
	}
	return status.New(codes.Unauthenticated, authnErrorMessage)
}

// operationalCode reports the wire code to use when a cause describes the
// SERVICE rather than the credential, and codes.OK when it does not.
//
// Deliberately a short allow-list rather than "anything that is not NotFound".
// The codes left out are the ones an attacker could steer: NotFound is the
// enumeration case the opaque answer exists for, and PermissionDenied /
// Unauthenticated from something downstream are refusals wearing another
// service's label. A new code shows up as a refusal — the safe default — and
// is added here deliberately if it turns out to be an outage.
func operationalCode(cause error) codes.Code {
	if cause == nil {
		return codes.OK
	}
	st, ok := status.FromError(cause)
	if !ok {
		// Not a status error at all: a sentinel from this package, which is
		// always a refusal.
		return codes.OK
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted, codes.Internal:
		return codes.Unavailable
	default:
		return codes.OK
	}
}

// Unwrap exposes the cause to errors.Unwrap / errors.Is /
// errors.As. The cause is intentionally opaque to the wire —
// only handler-side observers (logs, traces, audits) see it.
func (e *authnError) Unwrap() error {
	return e.cause
}

// Unauthenticated returns an opaque codes.Unauthenticated /
// "invalid credentials" status error suitable for any
// authentication-flow failure. The cause is preserved via
// errors.Unwrap for handler-side logging only — it never
// reaches the wire.
//
// Anti-enumeration: every failure path of an auth handler MUST
// return this; the same opaque wire shape for every REFUSAL
// (header missing, password mismatch, no such account, …) is
// what prevents a probing attacker from distinguishing "no
// such email" from "wrong password".
//
// An OUTAGE is not a refusal and is no longer folded in with
// them — see GRPCStatus. Callers do not have to classify:
// passing the upstream error through here is still the whole
// contract, and the classification happens once, on the way
// to the wire.
//
// Pass nil when the failure has no underlying error (e.g.
// header validation gate that just trips on shape).
//
// Originally lived in sdk/go/plugin; moved into the plugin
// itself in the v4 cleanup since this auth plugin is the only
// caller. Other plugins that want the same anti-enumeration
// contract copy the helper into their own handlers/ tree —
// short enough to inline, and lets each plugin tune behaviour
// (e.g. swap codes.PermissionDenied for some flows) without
// pulling the shared dep.
func Unauthenticated(cause error) error {
	return &authnError{cause: cause}
}
