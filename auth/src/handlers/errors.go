package handlers

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	"github.com/wandering-compiler/sdk/go/lib/i18n"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
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

	// userCode / userMsg are the pair a REST gateway renders for a person.
	// EMPTY unless a flow-specific constructor set them, and that default is
	// the safe one: the generic constructor serves 87 call sites across MFA,
	// reset tokens, OAuth, API tokens and invites, so any sentence put here
	// would be wrong for most of them.
	userCode string
	userMsg  string
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
// first two belong together; the third is not a refusal at all. A facade that
// wants to tell an outage from a rejection cannot, if the information is
// destroyed here — so a running service, with its database down, tells people
// their password is wrong. That is a lie they cannot check, and it sends them
// to reset a password that was fine.
//
// Nothing leaks: the operational answer is the same for every caller and every
// address, so "the service is degraded" says nothing about whether an account
// exists. The classification is on the CAUSE's own status code, and only codes
// that describe the service rather than the credential flip.
func (e *authnError) GRPCStatus() *status.Status {
	if st, ok := deliberateStatus(e.cause); ok {
		return st
	}
	if c := operationalCode(e.cause); c != codes.OK {
		return withUserDetail(status.New(c, "the authentication service is temporarily unavailable"),
			CodeAuthUnavailable, MsgAuthUnavailable)
	}
	st := status.New(codes.Unauthenticated, authnErrorMessage)
	if e.userCode == "" {
		// No flow claimed this refusal, so we say nothing rather than guess.
		// The gateway renders its generic sentence for the code, which for a
		// bearer/session failure — the bulk of these — is exactly right.
		return st
	}
	return withUserDetail(st, e.userCode, e.userMsg)
}

// Codes a caller may branch on. Stable, and narrow ON PURPOSE: the pair below
// is the whole vocabulary of this package's opaque answer, because telling
// them apart is the one distinction an auth surface is allowed to make.
//
// CodeInvalidCredentials deliberately does not say WHICH half was wrong —
// that is the anti-enumeration rule this file exists for, and it is why the
// sentence beside it names both.
//
// Only SIGN-IN mints CodeInvalidCredentials. Every other flow that refuses —
// a missing bearer header, a bad MFA code, a spent reset token — goes out
// with no detail at all and renders the gateway's generic sentence. That is
// deliberate: those flows want their own wording, and inventing it here from
// the cause is how the anti-enumeration rule gets broken by accident (see
// UnauthenticatedSignIn).
const (
	CodeInvalidCredentials = "INVALID_CREDENTIALS" // #nosec G101 -- the NAME of the code a client dispatches on, not a credential value
	CodeAuthUnavailable    = "AUTH_UNAVAILABLE"

	// CodeEmailNotVerified is a REFUSAL THE CALLER CAN ACT ON, which is why
	// it is not folded into the opaque pair above. It describes the caller's
	// own account — an address they already know they own or do not — so it
	// tells an attacker nothing they did not arrive with.
	CodeEmailNotVerified = "EMAIL_NOT_VERIFIED"

	// CodeOrgNotMember: the credential was ACCEPTED, and the organization the
	// request named (W17-Org) is not one the caller belongs to or owns. Not
	// folded into the opaque answer, because it is not a credential refusal:
	// it used to render "You are not signed in." to a caller who was, and
	// whose real mistake — usually an org ID where the slug goes — that
	// sentence hides. It reveals nothing: an org that does not
	// exist and one the caller is not in answer the same.
	CodeOrgNotMember = "ORG_NOT_MEMBER"

	// CodeOrgMismatch: the request's `org` field names a different
	// organization than the one authentication resolved for it. Through
	// REST the two cannot differ (the gateway makes the path's org the
	// W17-Org it authenticates); a gRPC caller can send one org in the field
	// and another in its metadata, and acting in either would be a guess.
	CodeOrgMismatch = "ORG_MISMATCH"

	// CodeEmailTaken: registration of an address that already has an account.
	// Said where the caller already proved the address or could learn it
	// anyway: plain SignUp creates the account on the spot, so the outcome IS
	// the answer; under sign_up_confirmation only ConfirmSignUp says it, to
	// whoever holds the code mailed to that address.
	CodeEmailTaken = "EMAIL_TAKEN"

	// CodeEmailInvalid: an address no account may be given. Today that is the
	// domain erased accounts are re-addressed to (erasedEmailDomain): an
	// account holding `erased-<id>@erased.invalid` before the account with
	// that id is erased would block its erasure for good (the address is
	// unique).
	CodeEmailInvalid = "EMAIL_INVALID"

	// CodeClientRevoked: registering a (client_id, redirect_uri) pair whose
	// registration was revoked. A revoked registration is history and is not
	// reused; the operator registers the callback under another client_id.
	CodeClientRevoked = "CLIENT_REVOKED"

	// CodeRoleAboveCaller: a role the caller tried to hand out (an invitation,
	// a grant) carries permissions the caller does not hold. Reached only by a
	// caller already allowed to grant at all, so it names a rule they can act
	// on — and without it they read the generic "You do not have access to
	// this." about an endpoint they DO have access to.
	CodeRoleAboveCaller = "ROLE_ABOVE_CALLER"

	// CodeTenantUnknown: under tenant_scope, a registration whose host (or
	// {tenant_slug}) names no tenant. Not a credential refusal and not the
	// server's fault — the request came in on an address this deployment
	// does not serve.
	CodeTenantUnknown = "TENANT_UNKNOWN"

	// CodeTotpUnavailable: this deployment offers no authenticator app
	// (two_factor_totp=false, or no seed key configured).
	CodeTotpUnavailable = "TOTP_UNAVAILABLE"

	// CodeTotpNotEnrolled: an operation that belongs to an authenticator
	// (recovery codes) asked for by an account that has none confirmed.
	CodeTotpNotEnrolled = "TOTP_NOT_ENROLLED"

	// CodeTotpAlreadyConfirmed: ConfirmTotp for an authenticator that is
	// already confirmed (new recovery codes are GenerateRecoveryCodes).
	CodeTotpAlreadyConfirmed = "TOTP_ALREADY_CONFIRMED"

	// CodeStepUpLocked: too many wrong codes for a change to the
	// authenticator; it is refused for a while, whatever the code.
	CodeStepUpLocked = "STEP_UP_LOCKED"

	// CodeSessionRequired: an operation that creates a credential (an API
	// token, a CLI session, an authenticator, recovery codes, a trusted
	// callback) called with an API token. It needs a signed-in session.
	CodeSessionRequired = "SESSION_REQUIRED"

	// CodePasswordNotConfirmed: ConfirmPassword (step_up) was given a password
	// that is not the caller's.
	CodePasswordNotConfirmed = "PASSWORD_NOT_CONFIRMED"

	// CodePasswordStepUpLocked: too many wrong passwords to ConfirmPassword
	// in this session (step_up); it is locked for a while.
	CodePasswordStepUpLocked = "PASSWORD_STEP_UP_LOCKED"

	// CodeSignUpNotInvited: under invite_only, a registration with no
	// pending invitation for its address and no valid invitation link.
	CodeSignUpNotInvited = "SIGNUP_NOT_INVITED"

	// CodeInviteOtherAddress: the invitation link is bound to a different
	// address than the one registering. Says nothing about which address.
	CodeInviteOtherAddress = "INVITE_OTHER_ADDRESS"

	// CodeSignUpClosed: the address is outside sign_up_allowlist.
	CodeSignUpClosed = "SIGNUP_CLOSED"

	// The OAuth refusals below are said plainly because none of them tells
	// an attacker more than they already had. OAUTH_ACCOUNT_UNVERIFIED and
	// ACCOUNT_DISABLED are reached only after the provider proved the
	// caller owns the address (or the linked subject). OAUTH_EMAIL_UNVERIFIED
	// is NOT: the provider did not verify the address, so whoever controls
	// the profile can name any address. It answers what the refusal itself
	// already answered — the callback succeeds when no account holds the
	// address and refuses when one does — and adds nothing about the account.

	// CodeOAuthAccountUnverified: an account exists for the provider's
	// address, and that account never verified it, so it is not linked.
	CodeOAuthAccountUnverified = "OAUTH_ACCOUNT_UNVERIFIED"

	// CodeOAuthEmailUnverified: an account exists for the address, and the
	// provider did not verify it, so it is not linked.
	CodeOAuthEmailUnverified = "OAUTH_EMAIL_UNVERIFIED"

	// CodeAccountDisabled: the provider sign-in resolved to an account an
	// administrator disabled. Only OAuth says this; a password sign-in to a
	// disabled account stays INVALID_CREDENTIALS.
	CodeAccountDisabled = "ACCOUNT_DISABLED"

	// CodeOAuthFailed: every other OAuth refusal — the state, the login code,
	// the verifier, the provider's answer. The sign-in starts again.
	CodeOAuthFailed = "OAUTH_FAILED"

	// CodeSessionExpired: the bearer is a token this deployment issued and
	// it is past its expires_at — sign in again (or, for an API token, create
	// a new one). Not folded into the opaque answer: an expired token is not a
	// guess, and "invalid credentials" sent its holder looking for what was
	// wrong with a credential that had merely run out. It reveals nothing the
	// holder lacked — they hold the token, and its expiry is a property of it.
	// An UNKNOWN token still answers the opaque refusal with no detail.
	// Also the ErrorInfo reason (domain ErrorDomain), which a client reads
	// together with the expires_at metadata.
	CodeSessionExpired = "SESSION_EXPIRED"

	// The device-binding refusals. Every token is bound to the key of the
	// device it was issued to (DPoP, RFC 9449), and each of these tells the
	// client what to do with its key; all three are also the ErrorInfo reason
	// (domain ErrorDomain).
	//
	// CodeDeviceProofRequired: no proof of possession where one is needed —
	// a mint request, or an authenticated request (no proof, or the token
	// sent as Bearer). Decided before any token lookup. A token proved by
	// another key, or bound to none (minted before device binding), gets the
	// opaque refusal instead, like an unknown one: its thief learns nothing.
	CodeDeviceProofRequired = "DEVICE_PROOF_REQUIRED"

	// CodeDeviceRevoked: the device was revoked, for good. The client
	// discards its key, generates a new one and signs in again as a new
	// device.
	CodeDeviceRevoked = "DEVICE_REVOKED"

	// CodeDeviceKeyRequired: an API token (CreateApiToken, IssueBotToken)
	// asked for without the public key of the client that will use it. Every
	// token is bound to a device key, so none is minted unbound.
	CodeDeviceKeyRequired = "DEVICE_KEY_REQUIRED"
)

// The refusals of the key an API token's request names (CreateApiToken,
// IssueBotToken). ErrorDetail only, never a google.rpc.ErrorInfo and never
// Unauthenticated: they are about the key in the request body, not the
// caller's own device, so a client must not read them as "my key is gone".
const (
	// CodeDeviceKeyInvalid: public_key is not a public P-256 or Ed25519 JWK
	// (malformed, another key type or curve, a point off the curve), carries a
	// private member, or is the key of a device that signs in to the account.
	CodeDeviceKeyInvalid = "DEVICE_KEY_INVALID"
	// CodeDeviceKeyRevoked: the key names a device of the token's owner that
	// was revoked, for good. The program generates a new key.
	CodeDeviceKeyRevoked = "DEVICE_KEY_REVOKED"
	// CodeBotKeyMismatch: the machine account already has a key and the
	// request names another (device/bot-one-key). Its replicas share the one
	// key; to replace it, revoke the account's device first.
	CodeBotKeyMismatch = "BOT_KEY_MISMATCH"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of the refusals this plugin
// describes with one.
const ErrorDomain = "auth.w17"

// The sentences a person reads, and the ONE place each is written.
//
// `//w17:msgid` marks a string as translatable. Nothing harvests a plugin's
// Go — that runs in the consumer's binary, and harvesting happens on the
// console — so `make plugin-msgids-sync` mirrors these into plugin.yaml, where
// codegen can put them in a project's .po, and `make check-plugin-msgids`
// fails if the mirror drifts from what is here.
//
// Write a new user-facing sentence as a constant in this block. One written
// inline at a call site is invisible to the sync, reaches no catalog, and
// renders in English in every locale with nothing reporting it.
//
//w17:msgid
const (
	// Names BOTH halves on purpose: the anti-enumeration rule of this file,
	// expressed in the text. "No account with that email" would be friendlier
	// and would be an email oracle.
	MsgInvalidCredentials = "Wrong email or password." // #nosec G101 -- the SENTENCE a person reads, not a credential value

	// Flow-neutral. Every auth flow reaches the outage branch, so a sentence
	// naming sign-in would be wrong for a bad MFA code or a spent reset token.
	MsgAuthUnavailable = "Authentication is temporarily unavailable. Please try again shortly."

	// Names the header and what it takes, because the usual cause is an
	// organization's ID sent where its slug belongs.
	MsgOrgNotMember = "You are not a member of the organization this request names. The W17-Org header takes the organization's slug."

	MsgOrgMismatch = "This request names two different organizations. Name one."

	MsgSignUpNotInvited = "Registration is by invitation only. Ask the organization you are joining to invite you."

	MsgInviteOtherAddress = "This invitation is for a different email address, or has already been used. Ask for a new invitation."

	MsgSignUpClosed = "Registration is not open for this email address."

	MsgOAuthAccountUnverified = "An account with this email address exists but has not verified it. Sign in with your password and verify the address first."

	MsgOAuthEmailUnverified = "An account with this email address exists, and the sign-in provider has not verified the address. Sign in with your password instead."

	MsgAccountDisabled = "This account has been disabled."

	MsgOAuthFailed = "Signing in with the provider did not complete. Please start again."

	// Not "try again": the generic AlreadyExists sentence ("Another change
	// reached this first. Please try again.") sent a person who already has an
	// account round the registration form instead of to sign-in.
	MsgEmailTaken = "An account with this address already exists. Sign in instead."

	MsgEmailInvalid = "This email address cannot be used. Use another address."

	MsgClientRevoked = "This callback was registered under this client ID and revoked. Register it under a new client ID."

	MsgRoleAboveCaller = "That role carries permissions you do not hold. A role can be granted only by someone who holds everything it grants."

	// Minting for a machine account whose role the operator could not grant —
	// the token would act beyond the operator's own permissions.
	MsgBotAboveCaller = "This machine account holds a role with permissions you do not hold, so you cannot issue a token for it."

	MsgTenantUnknown = "This address does not belong to any organization here. Check the address you registered on."

	MsgTotpUnavailable = "Authenticator apps are not available here. Your sign-in codes arrive by message instead."

	MsgTotpNotEnrolled = "Set up an authenticator app first. Recovery codes belong to it."

	MsgTotpAlreadyConfirmed = "This authenticator app is already set up. To get new recovery codes, generate them."

	MsgStepUpLocked = "Too many wrong codes. Wait 15 minutes and try again."

	// Names what to do instead: the caller holds a working credential, just
	// not one this operation accepts.
	MsgSessionRequired = "Sign in to do this. An API token cannot create credentials."

	// step_up: the password the caller typed to confirm it is them is not
	// theirs. Says no more than that — they are signed in already.
	MsgPasswordNotConfirmed = "That is not your password. Type the password you sign in with."

	MsgPasswordStepUpLocked = "Too many wrong passwords. Wait 15 minutes and try again." //nolint:gosec // G101: a message about passwords, not one

	// {date} is the expiry, UTC. Names the remedy, which differs by kind: a
	// session is renewed by signing in, an API token only by minting another.
	MsgSessionExpired  = "Your session expired on {date}. Sign in again."
	MsgAPITokenExpired = "This API token expired on {date}. Create a new token." // #nosec G101 -- the SENTENCE a person reads, not a credential value

	// The device-binding refusals. A person reads them when their app could
	// not (or no longer may) prove which device it runs on; the remedy is
	// always the same — sign in again — and the app does the key handling.
	MsgDeviceProofRequired = "This app did not prove which device it runs on. Reload or update it, then sign in again."
	MsgDeviceRevoked       = "This device was signed out for good. Sign in again to use it as a new device."

	// An API token is bound to the key of the program that will use it. The
	// remedies name what to send: its PUBLIC key, never the private one.
	MsgClientKeyNeeded  = "Give the public key of the program that will use this token."
	MsgClientKeyInvalid = "That public key cannot be used. Give a P-256 or Ed25519 public key as a JWK."
	MsgClientKeyPrivate = "That key contains its private part. Give only the public key, and keep the private key where the program runs."
	MsgClientKeyRevoked = "That key belongs to a device that was revoked. Generate a new key for the program."
	MsgClientKeySignsIn = "That key belongs to a device you sign in with. Generate a separate key for the program."
	MsgBotKeyMismatch   = "This machine account already has a different key. Use that key, or revoke the account's device to replace it."
)

// isEmailTaken reports whether creating an account failed on the address's
// unique index.
//
// Storage reports a unique violation as InvalidArgument carrying an
// ErrorDetail{code: UNIQUE_VIOLATION} (grpcerr folds every validation-class
// violation into InvalidArgument), never as AlreadyExists. A check for
// AlreadyExists alone therefore never fires against a real store: handler tests
// pass because their fake store answers AlreadyExists, and live the caller
// reads "The request could not be accepted as sent.". AlreadyExists is still
// accepted, for a store that answers that way.
//
// The field is the address — or, under tenant_scope, the composite that
// includes it; a unique violation on some other column is not this refusal.
func isEmailTaken(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.AlreadyExists:
		return true
	case codes.InvalidArgument:
		for _, d := range st.Details() {
			if ed, ok := d.(*w17pb.ErrorDetail); ok && ed.GetCode() == "UNIQUE_VIOLATION" &&
				(ed.GetField() == "" || strings.Contains(ed.GetField(), "email")) {
				return true
			}
		}
	}
	return false
}

// erasedEmailDomain is the domain an erased account's address is replaced
// with (erasedAddress, `user_admin`). `.invalid` is reserved (RFC 2606), so no
// real mailbox is in it; refuseReservedEmail keeps every other path from
// writing it.
const erasedEmailDomain = "erased.invalid"

// refuseReservedEmail refuses an address in erasedEmailDomain, at every path
// that gives an account an address (SignUp, ConfirmSignUp, the OAuth account
// creation, the admin's UpdateAccount, CreateBot). Only an erasure writes one:
// an account that held `erased-<id>@erased.invalid` first would make the
// erasure of account <id> fail on the unique address for good.
func refuseReservedEmail(ctx context.Context, email string) error {
	if strings.HasSuffix(normalizeEmail(email), "@"+erasedEmailDomain) {
		return refusal(ctx, codes.InvalidArgument,
			"the "+erasedEmailDomain+" domain is reserved for erased accounts",
			CodeEmailInvalid, "email", MsgEmailInvalid, nil)
	}
	return nil
}

// emailTaken is the refusal for registering an address that has an account.
func emailTaken(ctx context.Context) error {
	return refusal(ctx, codes.AlreadyExists,
		"an account with this address already exists — sign in instead",
		CodeEmailTaken, "email", MsgEmailTaken, nil)
}

// withUserDetail attaches the pair a REST gateway renders for a person.
//
// Attached only when a flow asked for it, or for an outage — never as a
// blanket default. The status MESSAGE is unchanged either way: it is the
// operator's copy, and everything about the opaque answer above still holds
// for it.
//
// ⚠️ NOT TRANSLATED. i18n.T needs the request context and this runs from
// GRPCStatus(), which has none — threading one would mean changing
// Unauthenticated() at 87 call sites for no other reason. It renders in
// English until plugin-authored msgids can be harvested into project
// catalogs, which nothing supports yet.
func withUserDetail(st *status.Status, code, message string) *status.Status {
	with, err := st.WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{
		Code:    code,
		Message: message,
	}))
	if err != nil {
		// coverage-exempt: WithDetails only fails if the detail cannot
		// marshal, and ErrorDetail is a static well-typed proto.
		return st
	}
	return with
}

// wireError is a refusal this package mints when it has DECIDED that the
// caller may be told what happened. It is the narrow exception to the opaque
// answer, and the rule for minting one is a single sentence:
//
//	Only for a refusal that is reached AFTER the credential was proven.
//
// Past that point the caller already knows the password is right, so a clear
// answer tells an attacker nothing they did not buy with the credential — and
// telling the legitimate user "you asked for too many codes, wait" instead of
// "invalid credentials" is the difference between a hint and a lie. Refusals
// on the way TO proving the credential (no such email, wrong password, header
// gates) must NOT use this; they are the enumeration surface the opaque answer
// exists for.
//
// It is a package-private TYPE rather than a status code check on purpose. A
// cause that merely CARRIES some code can arrive from anything downstream, so
// classifying on the code would let another service steer the wire answer;
// only code in this package can construct a wireError.
type wireError struct {
	code codes.Code
	msg  string
}

func (e *wireError) Error() string { return e.msg }

// deliberateStatus reports the status a wireError anywhere in the cause chain
// asks for. Not a status.FromError call: that would also match a status error
// from a downstream service.
func deliberateStatus(cause error) (*status.Status, bool) {
	var we *wireError
	if errors.As(cause, &we) {
		return status.New(we.code, we.msg), true
	}
	var se *statusError
	if errors.As(cause, &se) {
		return se.st, true
	}
	return nil, false
}

// statusError is a wireError that carries a whole status, details included,
// for a refusal whose details need the request context to build (a translated
// ErrorDetail) — GRPCStatus has none. Same rule as wireError: only this
// package constructs one, so nothing downstream can steer the wire answer.
type statusError struct{ st *status.Status }

func (e *statusError) Error() string { return e.st.Message() }

func (e *statusError) GRPCStatus() *status.Status { return e.st }

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

// UnauthenticatedSignIn is Unauthenticated for the four gates a SIGN-IN
// rejects on, and the only place CodeInvalidCredentials is minted.
//
// Everything about the opaque answer is unchanged — same code, same status
// message, same cause handling. The one addition is the pair a gateway can
// render, because "You are not signed in." beside a login form the caller
// just submitted is true, useless and confusing.
//
// Use it ONLY where a rejection means the submitted credential was refused:
// no such account, wrong password, bot gate, disabled gate. All four must
// carry the IDENTICAL pair or this file's whole purpose is defeated — a
// different sentence for "no such account" than for "wrong password" is an
// email enumeration oracle wearing a friendly face.
//
// Do NOT use it for failures reached after the credential was accepted
// (device resolution, the MFA gate, session issue). They are not credential
// refusals, so the sentence would be a lie; they stay generic.
//
// Why a constructor rather than classifying on the cause in GRPCStatus, next
// to the outage check: the four gates do not share a sentinel — "no such
// account" arrives as whatever the query returned. A cause-keyed table would
// match the wrong-password sentinel and miss the missing-account one, which
// is precisely the pair that has to be indistinguishable. The flow knows; the
// cause does not.
func UnauthenticatedSignIn(cause error) error {
	return &authnError{
		cause:    cause,
		userCode: CodeInvalidCredentials,
		userMsg:  MsgInvalidCredentials,
	}
}

// UnauthenticatedOrgNotMember is the refusal of a request scoped into an
// organization the caller does not belong to. Same code and status message as
// every other authentication refusal — the contract — plus the pair a gateway
// renders, so the person reads what is actually wrong. Here rather than beside
// its caller because this file is staged with every feature.
func UnauthenticatedOrgNotMember(cause error) error {
	return &authnError{cause: cause, userCode: CodeOrgNotMember, userMsg: MsgOrgNotMember}
}

// refusal is a status whose message is the operator's copy and whose
// ErrorDetail is the person's. Here, not beside its first caller, because this
// file is staged with every feature and its callers are not — translated through the project's catalog, with
// the request field it is about, so a form can put it next to the input.
func refusal(ctx context.Context, c codes.Code, dev, code, field, msgid string, params map[string]string) error {
	st := status.New(c, dev)
	with, err := st.WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{
		Code:    code,
		Message: i18n.T(ctx, msgid, params),
		Field:   field,
	}))
	if err != nil {
		// coverage-exempt: WithDetails only fails if the detail cannot
		// marshal, and ErrorDetail is a static well-typed proto.
		return st.Err()
	}
	return with.Err()
}

// refuseOtherOrg refuses a request whose `org` field names a different
// organization than the one authentication resolved (scope `org_slug`). An
// empty field defers to authentication, and so does a request with NO
// resolved org: the field cannot select one (selection happens at
// authentication), and the handler's own activeOrgID answers that case with
// "send the W17-Org header" — "two different organizations" would describe a
// request that named only one (a gRPC or MCP caller filling `org` alone).
// Here rather than beside its callers because membership and invitation
// handlers both call it, and this file is staged with every feature.
func refuseOtherOrg(ctx context.Context, org string) error {
	if org == "" {
		return nil
	}
	slug, ok := principal.Scope(ctx, "org_slug")
	if !ok || slug == org {
		return nil
	}
	return refusal(ctx, codes.InvalidArgument,
		"request field org "+org+" is not the organization this request was authenticated in",
		CodeOrgMismatch, "org", MsgOrgMismatch, nil)
}
