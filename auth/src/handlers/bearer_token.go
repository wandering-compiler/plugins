package handlers

import (
	"context"
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
// in the clear and reported with an empty storedHash. Best effort: a failed
// move leaves the row as it was, still valid, and the next request using the
// token tries again; it does not fail the request it rides on. hash is
// sha256Hex(token), already computed for the lookup.
func (h *AuthServiceHandler) upgradeLegacyToken(ctx context.Context, token, hash, storedHash string) {
	if storedHash != "" || token == "" {
		return
	}
	_, _ = h.Mutation.UpgradeTokenHash(ctx, &pb.UpgradeTokenHashReq{LegacyToken: token, TokenHash: hash})
}

// expiredTokenRefusal turns a failed live lookup into SESSION_EXPIRED when the
// token is a row that exists and has expired, and returns lookupErr unchanged
// otherwise. Only a NotFound is looked into: an outage stays an outage, and a
// token that is unknown or was revoked stays the opaque refusal with no detail.
// The miss-path lookup is the caller's (one per resolver, so each reads the
// kind it can); a failure of it, or no expired row, is the opaque refusal too.
//
// Nothing here touches the row: an expired token is never moved to the hash
// (upgradeLegacyToken) or stamped as used.
func expiredTokenRefusal(ctx context.Context, lookupErr error, lookupExpired func() (*timestamppb.Timestamp, pb.TokenType, error)) error {
	if status.Code(lookupErr) != codes.NotFound {
		return lookupErr
	}
	expiresAt, kind, err := lookupExpired()
	if err != nil || expiresAt == nil {
		return lookupErr
	}
	return sessionExpired(ctx, expiresAt.AsTime(), kind)
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
	st := status.New(codes.Unauthenticated, dev)
	with, err := st.WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{
		Code:    CodeSessionExpired,
		Message: i18n.T(ctx, msgid, map[string]string{"date": expiresAt.Format("2006-01-02 15:04 UTC")}),
	}))
	if err != nil {
		// coverage-exempt: WithDetails only fails if the detail cannot
		// marshal, and ErrorDetail is a static well-typed proto.
		return &statusError{st: st}
	}
	sp := with.Proto()
	sp.Details = append(sp.Details, errorInfoAny(CodeSessionExpired, ErrorDomain,
		map[string]string{"expires_at": expiresAt.Format(time.RFC3339)}))
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
