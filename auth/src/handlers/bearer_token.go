package handlers

import (
	"context"
	"errors"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/i18n"
	"github.com/wandering-compiler/sdk/go/lib/randstr"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// bearerTokenLen is the length of a minted bearer token, the same shape the
// tokens have always had.
const bearerTokenLen = 64

// newBearerToken mints a bearer token: the token the caller is handed once,
// and the sha256 the store keeps. Nothing stores the token itself, so whoever
// reads the UserToken table or a backup of it has nothing to present.
func newBearerToken() (token, hash string, err error) {
	token, err = randstr.Token(bearerTokenLen)
	if err != nil {
		return "", "", err
	}
	return token, sha256Hex(token), nil
}

// upgradeLegacyToken moves the row a bearer resolved to onto the hash when it
// is a legacy row — minted before tokens were hashed, so found by its token
// in the clear and reported with an empty storedHash. Authenticate calls it
// only after the request passed every check, the device binding included, so
// a refused request never writes. Best effort: a failed
// move leaves the row as it was, still valid, and the next request using the
// token tries again; it does not fail the request it rides on. hash is
// sha256Hex(token), already computed for the lookup.
func (h *AuthServiceHandler) upgradeLegacyToken(ctx context.Context, token, hash, storedHash string) {
	if storedHash != "" || token == "" {
		return
	}
	_, _ = h.Mutation.UpgradeTokenHash(ctx, &pb.UpgradeTokenHashReq{LegacyToken: token, TokenHash: hash})
}

// endedToken is what the miss-path lookup reads off a presented token that
// exists but has ENDED: expired, or revoked. A revoked token is refused exactly
// as an expired one — nothing in the auth tables is deleted, so the row is
// still there to read, and its holder hears the same answer either way.
type endedToken struct {
	expiresAt  *timestamppb.Timestamp // nil: never expires
	revokedAt  *timestamppb.Timestamp // nil: not revoked
	kind       pb.TokenType
	thumbprint string // the key it is bound to; "" = none
	// When the device the token is bound to was revoked; nil = live.
	deviceRevokedAt *timestamppb.Timestamp
}

// endedAt is when the token stopped being valid: the earlier of its revocation
// and an expiry already past, nil when it has done neither (the lookup should
// not have returned it). A token revoked after it had expired ended at its
// expiry; one revoked before its expiry ended when it was revoked.
func (t endedToken) endedAt(now time.Time) *timestamppb.Timestamp {
	var expired *timestamppb.Timestamp
	if t.expiresAt != nil && !t.expiresAt.AsTime().After(now) {
		expired = t.expiresAt
	}
	switch {
	case t.revokedAt == nil:
		return expired
	case expired == nil || t.revokedAt.AsTime().Before(expired.AsTime()):
		return t.revokedAt
	default:
		return expired
	}
}

// expiredTokenRefusal turns a failed live lookup into an *expiredTokenError when the
// token is a row that exists and has ended (expired or revoked), and returns
// lookupErr unchanged otherwise. Authenticate answers it only to a request whose
// proof is by the key the token is bound to (expiredFor): SESSION_EXPIRED, or
// DEVICE_REVOKED when that device was revoked; to anyone else it is the opaque
// refusal, so a stolen token's state says nothing to the thief. Only a NotFound
// is looked into: an outage stays an outage, and a token that is unknown stays
// the opaque refusal with no detail. The miss-path lookup is the caller's (one
// per resolver, so each reads the kind it can); a failure of it, or no ended
// row, is the opaque refusal too.
//
// Nothing here touches the row: an ended token is never moved to the hash
// (upgradeLegacyToken) or stamped as used.
func expiredTokenRefusal(lookupErr error, lookupEnded func() (endedToken, error)) error {
	if status.Code(lookupErr) != codes.NotFound {
		return lookupErr
	}
	tok, err := lookupEnded()
	if err != nil {
		return lookupErr
	}
	ended := tok.endedAt(time.Now())
	if ended == nil {
		return lookupErr
	}
	return &expiredTokenError{
		expiresAt:     ended.AsTime(),
		kind:          tok.kind,
		thumbprint:    tok.thumbprint,
		deviceRevoked: tok.deviceRevokedAt != nil,
	}
}

// expiredTokenError is a presented token that exists and has ended: when, its
// kind, the key it is bound to and whether that device was revoked. It carries
// no wire status of its own, so whatever wraps it without deciding
// (Unauthenticated) answers the opaque refusal; expiredFor is the one place
// that may turn it into SESSION_EXPIRED or DEVICE_REVOKED.
type expiredTokenError struct {
	expiresAt     time.Time
	kind          pb.TokenType
	thumbprint    string
	deviceRevoked bool
}

func (e *expiredTokenError) Error() string { return "token expired or revoked" }

// expiredFor is the refusal for err when it is an ended token bound to the key
// jkt (the request's proof), and nil otherwise: DEVICE_REVOKED when the device
// was revoked — what a live token of that device answers, so revoking the
// device's tokens with it does not change what its holder is told — and
// SESSION_EXPIRED otherwise, the same for a revoked token as for an expired
// one.
func expiredFor(ctx context.Context, err error, jkt string) error {
	var exp *expiredTokenError
	if !errors.As(err, &exp) || exp.thumbprint == "" || !sameKey(exp.thumbprint, jkt) {
		return nil
	}
	if exp.deviceRevoked {
		return deviceRevoked(ctx)
	}
	return sessionExpired(ctx, exp.expiresAt, exp.kind)
}

// sessionExpired is the SESSION_EXPIRED refusal: Unauthenticated, with the
// ErrorDetail a person reads and the google.rpc.ErrorInfo a client dispatches
// on (reason SESSION_EXPIRED, domain ErrorDomain, metadata expires_at in
// RFC 3339 UTC). Both carry the same code so a client reading either agrees.
func sessionExpired(ctx context.Context, expiresAt time.Time, kind pb.TokenType) error {
	expiresAt = expiresAt.UTC()
	dev, msgid := "session expired; sign in again", MsgSessionExpired
	if kind == pb.TokenType_TOKEN_TYPE_API {
		dev, msgid = "API token expired; create a new token", MsgAPITokenExpired
	}
	return unauthenticatedWithInfo(ctx, CodeSessionExpired, dev, msgid,
		map[string]string{"date": expiresAt.Format("2006-01-02 15:04 UTC")},
		map[string]string{"expires_at": expiresAt.Format(time.RFC3339)})
}

// deviceProofRequired is the DEVICE_PROOF_REQUIRED refusal: a mint request
// without a proof of possession, or an authenticated request without one (no
// proof, or the token sent as Bearer) — decided before the token is looked
// up, so it says nothing about the token.
func deviceProofRequired(ctx context.Context) error {
	return unauthenticatedWithInfo(ctx, CodeDeviceProofRequired,
		"a DPoP proof of the device key is required", MsgDeviceProofRequired, nil, nil)
}

// deviceRevoked is the DEVICE_REVOKED refusal: the (user, device) pair was
// revoked, for good. Said only to the holder of the device's key (a sign-in
// that passed the password, or a request whose proof matched the binding).
func deviceRevoked(ctx context.Context) error {
	return unauthenticatedWithInfo(ctx, CodeDeviceRevoked,
		"this device was revoked; generate a new device key and sign in again", MsgDeviceRevoked, nil, nil)
}

// errDeviceNotRegistered is the cause behind a mint that found no device to
// bind to (the store answered no row). Never a token, always a refusal.
var errDeviceNotRegistered = errors.New("no device registered for the token")

// unauthenticatedWithInfo is an Unauthenticated refusal a client can act on:
// the ErrorDetail a person reads (the translated msgid) and the
// google.rpc.ErrorInfo a client dispatches on, both carrying code, the latter
// in ErrorDomain with info as its metadata. dev is the operator's copy.
func unauthenticatedWithInfo(ctx context.Context, code, dev, msgid string, params, info map[string]string) error {
	st := status.New(codes.Unauthenticated, dev)
	with, err := st.WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{
		Code:    code,
		Message: i18n.T(ctx, msgid, params),
	}))
	if err != nil {
		// coverage-exempt: WithDetails only fails if the detail cannot
		// marshal, and ErrorDetail is a static well-typed proto.
		return &statusError{st: st}
	}
	sp := with.Proto()
	sp.Details = append(sp.Details, errorInfoAny(code, ErrorDomain, info))
	return &statusError{st: status.FromProto(sp)}
}

// errorInfoTypeURL is the Any type URL of google.rpc.ErrorInfo.
const errorInfoTypeURL = "type.googleapis.com/google.rpc.ErrorInfo"

// errorInfoAny encodes a google.rpc.ErrorInfo by hand, in its wire form, as
// an Any status detail.
//
// By hand because the generated type cannot be imported here: this package
// is copied into the consumer's storage module, whose go.mod does not require
// the genproto module that holds errdetails, so importing it fails the
// consumer's build ("imported from implicitly required module"). The message
// is three fields and frozen, so the encoding is short:
//
//	1 reason   string
//	2 domain   string
//	3 metadata map<string,string> = repeated entry { 1 key, 2 value }
//
// Map entries are written in key order, so the bytes are deterministic.
func errorInfoAny(reason, domain string, metadata map[string]string) *anypb.Any {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, reason)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, domain)
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var entry []byte
		entry = protowire.AppendTag(entry, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, k)
		entry = protowire.AppendTag(entry, 2, protowire.BytesType)
		entry = protowire.AppendString(entry, metadata[k])
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendBytes(b, entry)
	}
	return &anypb.Any{TypeUrl: errorInfoTypeURL, Value: b}
}
