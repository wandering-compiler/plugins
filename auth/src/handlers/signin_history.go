package handlers

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Sign-in history — base tier, staged with every feature.
//
// Every sign-in attempt on every mint path (SignIn, SignUp when it issues a
// session, ConfirmSignUp, VerifyMfa, OAuthExchange, CliToken) appends exactly
// one SignInEvent row, whatever its outcome: success, a refusal before any
// account was looked up (no proof, an unknown address), a wrong password, a
// refused device. The table is append-only (only an erasure rewrites the
// personal columns of a row, EraseSignInEvents).
//
// Each path opens an attempt FIRST (beginSignIn) and closes it in a defer
// (endSignIn), so no return can skip the row and none can write two (a
// panic writes none: the request did not end in an answer):
//
//   - a SUCCESS writes its row inside the transaction that mints the session
//     (recordSignInOK, through mintSession or the path's own transaction), so
//     a session never exists without its history row: a failed history write
//     fails the mint, the transaction rolls back, and the defer records the
//     failure instead;
//   - every other end — a refusal, an outage, SignIn's mfa_required — is
//     written by the defer, on its own, after the answer is decided. A failed
//     write is logged and changes nothing the caller gets: the history is the
//     operator's record, never part of the answer, and both branches of the
//     anti-enumeration pair (an unknown address, a wrong password) write one
//     row each, so the write adds no timing difference between them. The
//     write is bounded (signInHistoryTimeout), so a stalled store cannot
//     hold a refusal past it.
//
// One edge writes two rows: a coordinator that applied the commit and then
// failed to acknowledge it leaves the OK row committed, and the defer, seeing
// the error, writes an ERROR row as well.
//
// An attempt at an ERASED account (a challenge, an OAuth or CLI code issued
// before the erasure, or the placeholder address typed at SignIn) is written
// pseudonymised, as the erasure left the account's other rows: the account's
// placeholder as the address, no client address, no user agent.
//
// The outcome is what the path set explicitly (an unknown address, a parked
// second factor, an exhausted attempt budget), or else read off the error the
// caller gets (signInOutcome): the refusal sentinels each feature registers,
// then the ErrorDetail code the wire carries, then the status code.

// signInAttempt is the row a mint path is building. Fields are filled as the
// path learns them; what is unknown when it ends stays empty (NULL).
type signInAttempt struct {
	method     pb.SignInMethod
	outcome    pb.SignInOutcome // set by the path; UNSPECIFIED = derive from the error
	address    string
	userID     string
	deviceID   string
	thumbprint string
	ip         string
	userAgent  string
	// account is the row of userID when the path read it with erased_at
	// (SignIn's lookup); otherwise endSignIn reads it if it needs to.
	account *pb.User
}

// signInHistoryTimeout bounds the write of a refusal's row (and the account
// read before it): the refusal waits for it, and a stalled store must not
// hold the answer longer than this. A variable for the tests.
var signInHistoryTimeout = 2 * time.Second

// signInAccountErased reports whether an account was erased. nil when
// `user_admin` is not staged: without it no account is ever erased, and no
// read is spent to find out. handlers/user_admin.go installs it.
var signInAccountErased func(user *pb.User) bool

// maxAddressLen is SignInEvent.address CHAR(320), the longest address the
// User table takes.
const maxAddressLen = 320

// beginSignIn opens the attempt of one mint request: its method, and what
// the request carries whatever happens next — the proof's key thumbprint
// (only a well-formed one: anything else is no proof), the client address
// and the user agent, taken as Device.ip / Device.label take them.
func beginSignIn(ctx context.Context, method pb.SignInMethod) *signInAttempt {
	md, _ := metadata.FromIncomingContext(ctx)
	a := &signInAttempt{method: method}
	if jkt := firstMeta(md, dpopJKTKey); validThumbprint(jkt) {
		a.thumbprint = jkt
	}
	a.userAgent, a.ip = deviceLabel(ctx)
	return a
}

// named records the address the attempt named, normalised as SignIn looks it
// up, as valid UTF-8, cut to the column on a rune boundary.
func (a *signInAttempt) named(address string) {
	a.address = truncate(strings.ToValidUTF8(normalizeEmail(address), ""), maxAddressLen)
}

// row is the RecordSignInEvent request for this attempt ending in outcome.
func (a *signInAttempt) row(outcome pb.SignInOutcome) *pb.RecordSignInEventReq {
	return &pb.RecordSignInEventReq{
		UserId:     a.userID,
		Address:    a.address,
		DeviceId:   a.deviceID,
		Thumbprint: a.thumbprint,
		Ip:         a.ip,
		UserAgent:  a.userAgent,
		Method:     a.method,
		Outcome:    outcome,
	}
}

// writeSignInEvent appends one history row. A variable only so the package's
// tests can tell the stores that keep the history from the many fakes that
// predate it (see TestMain); production never replaces it.
var writeSignInEvent = func(ctx context.Context, h *AuthServiceHandler, row *pb.RecordSignInEventReq) error {
	_, err := h.Mutation.RecordSignInEvent(ctx, row)
	return err
}

// recordSignInOK writes the success row of an attempt that minted a session
// for userID bound to dev, on txCtx — the transaction that minted it. Its
// error fails the mint. The attempt itself is left as it was: when the
// transaction rolls back, the account and device it names may not exist,
// and the failure row the defer then writes must not name them.
func (h *AuthServiceHandler) recordSignInOK(txCtx context.Context, a *signInAttempt, userID string, dev signInDevice) error {
	ok := *a
	ok.userID, ok.deviceID = userID, dev.id
	return writeSignInEvent(txCtx, h, ok.row(pb.SignInOutcome_SIGN_IN_OUTCOME_OK))
}

// endSignIn closes an attempt; every mint path defers it with its own
// result. A success (err nil, no outcome set) wrote its row with the session
// and writes nothing here. Anything else writes its one row now, on a
// context that a caller who hung up cannot cancel; a failed write is logged
// and the caller's answer stays what it was.
func (h *AuthServiceHandler) endSignIn(ctx context.Context, a *signInAttempt, err error) {
	outcome := a.outcome
	if outcome == pb.SignInOutcome_SIGN_IN_OUTCOME_UNSPECIFIED {
		if err == nil {
			return
		}
		outcome = signInOutcome(err)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signInHistoryTimeout)
	defer cancel()
	row := a.row(outcome)
	h.pseudonymiseErased(ctx, a, row)
	if werr := writeSignInEvent(ctx, h, row); werr != nil {
		slog.WarnContext(ctx, "auth: sign-in history row not written",
			"method", a.method.String(), "outcome", outcome.String(), "err", werr)
	}
}

// pseudonymiseErased rewrites a refusal's row for an account erased before
// the attempt: the address becomes the account's placeholder (an erased
// account's address IS its placeholder), the client address and user agent
// are dropped — what the erasure did to the account's earlier rows. The
// account is the path's own read when it has one with erased_at, else read
// here; a read that fails leaves the row as it is (it cannot tell).
func (h *AuthServiceHandler) pseudonymiseErased(ctx context.Context, a *signInAttempt, row *pb.RecordSignInEventReq) {
	if signInAccountErased == nil || row.GetUserId() == "" {
		return
	}
	user := a.account
	if user.GetId() != row.GetUserId() {
		got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: row.GetUserId()})
		if err != nil {
			return
		}
		user = got.GetUser()
	}
	if signInAccountErased(user) {
		row.Address, row.Ip, row.UserAgent = truncate(user.GetEmail(), maxAddressLen), "", ""
	}
}

// mintSession issues the session bearer bound to dev and writes the
// attempt's success row, in ONE transaction when the bundle has a
// coordinator (a generated bundle always has; a hand-built test handler
// runs the two calls in order). The token is returned only once both are
// written.
func (h *AuthServiceHandler) mintSession(ctx context.Context, a *signInAttempt, userID string, dev signInDevice, expiresAt *timestamppb.Timestamp) (string, error) {
	var token string
	err := h.inTx(ctx, func(txCtx context.Context) error {
		var err error
		if token, err = h.issueBoundToken(txCtx, userID, dev, expiresAt); err != nil {
			return err
		}
		return h.recordSignInOK(txCtx, a, userID, dev)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// inTx runs fn in one distributed transaction when the bundle has a
// coordinator (always, in a generated bundle), plainly otherwise; fn's error
// rolls it back. Shared by the mint paths and the two_factor writes.
func (h *AuthServiceHandler) inTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	if h.DistTx == nil {
		return fn(ctx)
	}
	tx, txCtx, err := distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection})
	if err != nil {
		return err
	}
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// outcomeRule maps a refusal sentinel anywhere in an error's chain to the
// outcome it records.
type outcomeRule struct {
	cause   error
	outcome pb.SignInOutcome
}

// signInOutcomeRules are checked first, in order. The base tier's own
// sentinels are here; each feature whose mint path refuses with sentinels of
// its own (two_factor, oauth, cli_login, sign_up_confirmation,
// service_account) appends its rules from its file's init(), so the list
// names only what the activation compiles.
var signInOutcomeRules = []outcomeRule{
	{errAuthnPasswordMismatch, pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_PASSWORD},
	{errAuthnUserDisabled, pb.SignInOutcome_SIGN_IN_OUTCOME_ACCOUNT_DISABLED},
}

// outcomeByCode maps the ErrorDetail code a refusal carries on the wire to
// the outcome it records.
var outcomeByCode = map[string]pb.SignInOutcome{
	CodeDeviceProofRequired:    pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_PROOF_REQUIRED,
	CodeDeviceRevoked:          pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_REVOKED,
	CodeEmailTaken:             pb.SignInOutcome_SIGN_IN_OUTCOME_EMAIL_TAKEN,
	CodeEmailInvalid:           pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED,
	CodeSignUpNotInvited:       pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED,
	CodeInviteOtherAddress:     pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED,
	CodeSignUpClosed:           pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED,
	CodeTenantUnknown:          pb.SignInOutcome_SIGN_IN_OUTCOME_SIGN_UP_REFUSED,
	CodeOAuthAccountUnverified: pb.SignInOutcome_SIGN_IN_OUTCOME_UNVERIFIED_EMAIL,
	CodeOAuthEmailUnverified:   pb.SignInOutcome_SIGN_IN_OUTCOME_UNVERIFIED_EMAIL,
	CodeAccountDisabled:        pb.SignInOutcome_SIGN_IN_OUTCOME_ACCOUNT_DISABLED,
	CodeClientRevoked:          pb.SignInOutcome_SIGN_IN_OUTCOME_CLIENT_REFUSED,
	CodeAuthUnavailable:        pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR,
}

// signInOutcome reads the outcome of a failed attempt off the error its
// caller gets: a registered sentinel in the chain; else the ErrorDetail code
// of the wire status; else the status code — a refusal code is REFUSED,
// anything else (an outage, an unexpected error) ERROR.
func signInOutcome(err error) pb.SignInOutcome {
	for _, r := range signInOutcomeRules {
		if errors.Is(err, r.cause) {
			return r.outcome
		}
	}
	st := status.Convert(err)
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			if o, ok := outcomeByCode[ed.GetCode()]; ok {
				return o
			}
		}
	}
	switch st.Code() {
	case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument,
		codes.NotFound, codes.AlreadyExists, codes.FailedPrecondition:
		return pb.SignInOutcome_SIGN_IN_OUTCOME_REFUSED
	}
	return pb.SignInOutcome_SIGN_IN_OUTCOME_ERROR
}

// ListMySignInEvents returns the caller's own sign-in history: the attempts
// that reached their account, newest first, the latest 100. The account is
// the envelope's, never a request field, so nobody reads another's history
// here; an attempt that reached no account (user_id NULL) is nobody's to
// read but the operator's (the admin Sign-ins page).
func (h *AuthServiceHandler) ListMySignInEvents(ctx context.Context, _ *pb.ListMySignInEventsReq) (*pb.ListMySignInEventsResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListUserSignInEvents(ctx, &pb.ListUserSignInEventsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &pb.ListMySignInEventsResp{Events: resp.GetEvents()}, nil
}
