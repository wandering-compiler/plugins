package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
)

// Storage constraint-violation detail codes (srcgo/lib/validation
// defaults). Every DB constraint violation surfaces as a
// codes.InvalidArgument gRPC status carrying a w17.ErrorDetail; the
// specific kind lives in ErrorDetail.code, NOT the top-level code.
const (
	codeUniqueViolation = "UNIQUE_VIOLATION" // duplicate key (PK / unique)
	codeInvalidValue    = "INVALID_VALUE"    // FK / CHECK constraint
)

// constraintCode returns the w17 ErrorDetail.code carried by a storage
// constraint-violation error, or "" if err is not one. This is the
// caller's only reliable discriminator — the top-level gRPC code is a
// uniform InvalidArgument across unique / FK / check.
func constraintCode(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return ""
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed.GetCode()
		}
	}
	return ""
}

// invalidArg returns a codes.InvalidArgument status for a caller-input
// failure (missing required field, etc.).
func invalidArg(msg string) error {
	return status.Error(codes.InvalidArgument, msg)
}

// notFound returns a codes.NotFound status.
func notFound(msg string) error {
	return status.Error(codes.NotFound, msg)
}

// providerFailure maps a backend/provider error onto a gRPC status by
// the failure class the driver reported (backend.ErrInvalidRequest /
// ErrDeclined, matched with errors.Is):
//
//   - invalid request → InvalidArgument: the request cannot succeed as
//     written (an amount the currency cannot carry, a refund above what
//     is left, an idempotency key reused with other parameters);
//   - declined → FailedPrecondition: the payment method was refused;
//   - anything else → Unavailable: network / provider outage, the caller
//     may retry.
//
// Every provider failure used to be Unavailable, and gRPC retry policies
// retry UNAVAILABLE automatically, so a declined card or an over-precise
// amount was resubmitted on a loop that could never succeed, and the
// caller was told "try again later" instead of why.
func providerFailure(cause error) error {
	code := codes.Unavailable
	switch {
	case errors.Is(cause, backend.ErrDeclined):
		code = codes.FailedPrecondition
	case errors.Is(cause, backend.ErrInvalidRequest):
		code = codes.InvalidArgument
	}
	return status.Errorf(code, "payment provider error: %v", cause)
}

// absent reports a single-row read that found nothing. Generated storage
// answers such a read with NotFound (QueryRow+Scan, sql.ErrNoRows mapped by
// grpcerr), never with an empty response — every lookup that may
// legitimately find nothing has to treat it as "no row", not as a failure.
func absent(err error) bool { return status.Code(err) == codes.NotFound }

// guardRefused reports whether err is the shape a transition-guarded
// statement produces when its WHERE matched no row: the generated
// single-row RETURNING scan gets sql.ErrNoRows and grpcerr.Wrap maps it
// to NotFound. Here (always staged) because both the webhook handler and
// the feature-gated hooks read it.
func guardRefused(err error) bool {
	return err != nil && status.Code(err) == codes.NotFound
}

// errNoLocalRecord is what a webhook reconciliation (core or a feature
// hook) returns when the provider object it names has no local row yet.
// IngestStripe answers it with NotFound and does NOT record the event,
// so the provider's redelivery runs the whole reconciliation again once
// the local INSERT has landed.
var errNoLocalRecord = errors.New("no local record for the provider object")

// ── amount helpers ─────────────────────────────────────────────────────────
//
// HERE, in a file no feature gates, and not beside their first caller.
//
// Both were declared in `prepaid.go` and used from `payment_service.go`
// (always staged) and `subscriptions.go` (feature `subscriptions`, which does
// not require `prepaid`). Features stage independently, so a project
// activating payment WITHOUT prepaid got those call sites without these
// functions and its bundle build failed on an undefined identifier — while
// everything compiled in this module, which has every file at once.
//
// Found by `make check-plugin-stage` on its first run; nobody had reported it,
// because it only breaks the combination nobody happened to try.

// Every monetary column is DECIMAL(20, 4) (models.proto): 16 integer
// digits, 4 fractional.
const (
	amountMaxIntDigits  = 16
	amountMaxFracDigits = 4
)

// isPositiveDecimal reports whether s is a non-zero, non-negative
// decimal string (digits + at most one dot) that the DECIMAL(20, 4)
// money columns hold EXACTLY. Grant/spend take an unsigned amount; the
// sign is the handler's to apply.
//
// The column bounds are part of "valid": a fifth fractional digit was
// accepted and then silently ROUNDED by the database (a grant of
// "0.00004" stored a zero-delta ledger row; "1.00005" became 1.0001),
// and an integer part past 16 digits passed validation, reached the
// provider, and only then failed the local INSERT — after the charge
// object existed.
func isPositiveDecimal(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	intPart, fracPart, hasDot := strings.Cut(s, ".")
	if hasDot && strings.Contains(fracPart, ".") {
		return false
	}
	nonZero := false
	for _, r := range intPart + fracPart {
		switch {
		case r >= '1' && r <= '9':
			nonZero = true
		case r == '0':
		default:
			return false
		}
	}
	if len(fracPart) > amountMaxFracDigits {
		return false
	}
	if len(strings.TrimLeft(intPart, "0")) > amountMaxIntDigits {
		return false
	}
	return nonZero
}

// sameDecimal compares two non-negative decimal strings by value, so the
// DECIMAL(20, 4) column's "29.0000" equals a request's "29" / "29.00". Here,
// not in subscriptions.go: RefundPayment (always staged) reads it too.
func sameDecimal(a, b string) bool {
	norm := func(s string) string {
		i, f, _ := strings.Cut(strings.TrimSpace(s), ".")
		return strings.TrimLeft(i, "0") + "." + strings.TrimRight(f, "0")
	}
	return norm(a) == norm(b)
}

// isCurrencyCode reports whether c (already trimmed + lowercased) has
// the ISO-4217 shape: exactly three ASCII letters. The currency column
// is CHAR(3); a longer code used to reach the provider first and fail
// the local INSERT only after the provider object existed.
func isCurrencyCode(c string) bool {
	if len(c) != 3 {
		return false
	}
	for i := 0; i < len(c); i++ {
		if c[i] < 'a' || c[i] > 'z' {
			return false
		}
	}
	return true
}

// maxIdempotencyKeyLen is both the idempotency_key column width
// (CHAR(255)) and the provider's own Idempotency-Key limit.
const maxIdempotencyKeyLen = 255

// idempotencyKeyTooLong rejects a key neither the column nor the
// provider can carry — before the provider call, not after it.
func idempotencyKeyTooLong(key string) error {
	if len(key) > maxIdempotencyKeyLen {
		return invalidArg("idempotency_key must be at most 255 bytes")
	}
	return nil
}

// scopedKey derives the stored ledger key from its scope and the
// caller's key: "v2:" + hex(sha256 of the parts, each length-prefixed).
// Fixed length (67 bytes, inside every key column), and two applies share
// a stored key only when every part matches. Length-prefixed rather than
// joined by a separator: any byte, NUL included, is valid in a caller's
// string, so with a separator ("u\x00v", "k") and ("u", "v\x00k") would
// hash alike.
func scopedKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	return scopedKeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// scopedKeyPrefix starts every scoped key. A caller's raw key with this
// prefix can equal a stored scoped key, so the lookups for keys stored raw by
// earlier versions skip it.
const scopedKeyPrefix = "v2:"

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// idempotencyKeyOrNew returns the caller's key, or a fresh random one
// when the caller sent none ("Empty → the handler derives one", the
// ChargeReq contract). The handler used to pass the empty string
// through: Payment.idempotency_key is UNIQUE, so the second key-less
// charge EVER created its provider object and then failed the local
// INSERT, and every key-less charge after it did the same. A derived key
// is unique per call, so it buys no retry safety — a caller that wants
// that supplies a stable key.
func idempotencyKeyOrNew(key string) string {
	if key != "" {
		return key
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms (Go 1.24+
		// crashes the program instead); unreachable in practice.
		panic("payment: crypto/rand: " + err.Error())
	}
	return "auto:" + hex.EncodeToString(b[:])
}
