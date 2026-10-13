package handlers

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Device binding — base tier, staged with every feature.
//
// Every token is bound to a device, and a device is the key its client signs
// DPoP proofs with (RFC 9449). The gateway verifies each proof and hands this
// plugin only the RFC 7638 thumbprint of the key that signed it:
//
//   - on a MINT request (SignIn, SignUp, ConfirmSignUp, VerifyMfa,
//     OAuthExchange, CliToken) as the gRPC metadata `x-w17-dpop-jkt`. The
//     handler registers the (user, thumbprint) Device and binds the new token
//     to it. No thumbprint, no token: the mint is refused with
//     DEVICE_PROOF_REQUIRED, so nothing here ever issues an unbound token.
//   - on every authenticated request as the header `x-w17-dpop-jkt` in
//     AuthReq.headers. Authenticate compares it with the thumbprint the token
//     is bound to (checkTokenBinding) and answers the binding as
//     AuthResp.device_id.
//
// Both keys are in the gateway-owned `x-w17-` namespace, which every surface
// strips from what a client sends, so a client can name a device only by
// holding its key.

const (
	// dpopJKTKey is the possession thumbprint the gateway stamps — metadata
	// key on a mint request, AuthReq header key on Authenticate (lower-case,
	// as the gateway folds header names).
	dpopJKTKey = "x-w17-dpop-jkt"

	// dpopScheme is the Authorization scheme of a bound token (RFC 9449 §7.1).
	// A bound token presented under any other scheme is refused: the gateway
	// verifies a proof only for this scheme, so a downgrade to Bearer can
	// never be mistaken for a proofed request.
	dpopScheme = "DPoP"

	// thumbprintLen is the length of an RFC 7638 SHA-256 thumbprint in
	// base64url without padding (32 bytes → 43 characters).
	thumbprintLen = 43
)

// Device-label metadata. The browser's User-Agent travels under
// x-forwarded-user-agent: the gRPC hop from the gateway replaces user-agent
// with its own ("grpc-go/…"). user-agent stays the fallback for an in-process
// call. Both are display only — nothing about a device's identity rests on
// them any more.
const (
	userAgentMetadataKey          = "user-agent"
	forwardedUserAgentMetadataKey = "x-forwarded-user-agent"
	clientIPMetadataKey           = "x-forwarded-for" // → Device.ip (first hop)

	maxLabelLen = 255 // Device.label CHAR(255)
	maxIPLen    = 45  // Device.ip CHAR(45)
)

// validThumbprint reports whether s has the shape of a SHA-256 JWK
// thumbprint: exactly 43 base64url characters. The gateway only ever stamps
// one of those; anything else is refused as no proof at all rather than
// stored as a device.
func validThumbprint(s string) bool {
	if len(s) != thumbprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// mintThumbprint is the thumbprint of the key that signed this mint
// request's proof, or the DEVICE_PROOF_REQUIRED refusal. Every mint path
// calls it FIRST — before a password is hashed, an attempt is counted or a
// single-use code is spent — so a client that cannot sign burns nothing.
func mintThumbprint(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	jkt := firstMeta(md, dpopJKTKey)
	if !validThumbprint(jkt) {
		return "", deviceProofRequired(ctx)
	}
	return jkt, nil
}

// signInDevice is what mintDevice found: the device's id, whether it is
// trusted, and — for a trusted one — the cutoff a renewal of that trust must
// hold against (see issueSession's trustCutoff).
type signInDevice struct {
	id          string
	trusted     bool
	trustCutoff *timestamppb.Timestamp
}

// mintDevice registers (or finds) the device the token about to be minted is
// bound to: the (user, thumbprint) pair, in one UPSERT that also refreshes
// its label, address and last-seen time.
//
// A REVOKED pair is refused with DEVICE_REVOKED, for good: reviving it would
// let whoever holds the stolen key and the password come back as a known,
// possibly trusted, device. The client answers by generating a new key — a
// new device, which passes the second factor like any other.
//
// Trust is the pair's: `trusted_at` later than the account's last trust
// revocation (a password change, a disable). The revocation is read only for
// a device that has trust to lose; a failed read means untrusted (one extra
// challenge, never a skipped one). A trusted device comes back with the
// revocation stamp it was judged against as its trust cutoff: renewing the
// trust must not outlive a revocation that commits after this read.
func mintDevice(ctx context.Context, h *AuthServiceHandler, userID, thumbprint string) (signInDevice, error) {
	label, ip := deviceLabel(ctx)
	resp, err := h.Mutation.RegisterDevice(ctx, &pb.RegisterDeviceReq{
		UserId:     userID,
		Thumbprint: thumbprint,
		Label:      label,
		Ip:         ip,
	})
	if err != nil {
		return signInDevice{}, err
	}
	dev := resp.GetDevice()
	if dev.GetId() == "" || dev.GetThumbprint() != thumbprint {
		// An UPSERT with RETURNING always answers the row of this key; none,
		// or a row of no key (a legacy device recorded before binding), is a
		// store that did not do what was asked, and no token is bound to it.
		return signInDevice{}, errDeviceNotRegistered
	}
	if dev.GetRevokedAt() != nil {
		return signInDevice{}, deviceRevoked(ctx)
	}
	out := signInDevice{id: dev.GetId()}
	if dev.GetTrustedAt() == nil {
		return out, nil
	}
	revokedAt, err := deviceTrustRevokedAt(ctx, h, userID)
	if err != nil || !trustOutlivesRevocation(dev.GetTrustedAt(), revokedAt) {
		return out, nil
	}
	out.trusted, out.trustCutoff = true, revokedAt
	if revokedAt == nil {
		out.trustCutoff = neverRevoked
	}
	return out, nil
}

// issueBoundToken mints a session token bound to deviceID, expiring at
// expiresAt, and returns the token the caller is handed once. The ONE place a
// session row is written, so there is no path that mints one unbound:
// IssueToken's request requires the device as well.
func (h *AuthServiceHandler) issueBoundToken(ctx context.Context, userID, deviceID string, expiresAt *timestamppb.Timestamp) (string, error) {
	if deviceID == "" {
		return "", errDeviceNotRegistered
	}
	token, hash, err := newBearerToken()
	if err != nil {
		return "", err
	}
	if _, err := h.Mutation.IssueToken(ctx, &pb.IssueTokenReq{
		UserId:    userID,
		DeviceId:  deviceID,
		ExpiresAt: expiresAt,
		TokenHash: hash,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// issueSession mints the session bearer for an authenticated principal,
// bound to the device mintDevice registered, with the session lifetime.
// Shared by SignIn, VerifyMfa and the OAuth exchange.
//
// trustCutoff says whether this sign-in may make the device trusted: nil means
// it may not. Only a sign-in that passed the plugin's second factor, or was not
// asked for one, may: a trusted device skips the second factor later
// (two_factor_scope=new_devices), so trust earned by a sign-in that skipped it
// — OAuth — would carry that skip over to password sign-ins from the same
// device. A non-nil cutoff is the instant the sign-in's checks are good for:
// the trust is written only if the account's device trust (a password change,
// a disable) was not revoked after it, so a revocation that commits while the
// sign-in is in flight is not undone by it.
//
// Trust is best effort: a failed TrustDevice leaves the device untrusted (it
// is challenged again next time) and does not fail the session just issued.
func issueSession(ctx context.Context, h *AuthServiceHandler, userID, deviceID string, trustCutoff *timestamppb.Timestamp) (string, error) {
	token, err := h.issueBoundToken(ctx, userID, deviceID, h.sessionTokenExpiry())
	if err != nil {
		return "", err
	}
	if trustCutoff != nil {
		_, _ = h.Mutation.TrustDevice(ctx, &pb.TrustDeviceReq{
			UserId:          userID,
			DeviceId:        deviceID,
			NotRevokedAfter: trustCutoff,
		})
	}
	return token, nil
}

// checkTokenBinding is Authenticate's device check, run once the token has
// resolved (so an unknown token stays the opaque refusal and none of these
// says whether a token exists). viaDPoP is whether the token came under the
// DPoP scheme; jkt is the thumbprint of the key that signed the request's
// proof, as the gateway passed it.
//
// The order is what each answer may reveal:
//
//  1. a token bound to no device — minted before device binding — is refused
//     with DEVICE_PROOF_REQUIRED: its holder signs in once more, with a key;
//  2. a bound token without a proof (no jkt, or presented as Bearer) is
//     refused the same way;
//  3. a proof by a key other than the bound one is DEVICE_MISMATCH, and says
//     nothing about the device — the caller does not hold its key;
//  4. only the holder of the bound key learns DEVICE_REVOKED, which tells
//     its client to generate a new key.
func checkTokenBinding(ctx context.Context, p *authPrincipal, viaDPoP bool, jkt string) error {
	if p.deviceThumbprint == "" || !viaDPoP || !validThumbprint(jkt) {
		return deviceProofRequired(ctx)
	}
	if subtle.ConstantTimeCompare([]byte(jkt), []byte(p.deviceThumbprint)) != 1 {
		return deviceMismatch(ctx)
	}
	if p.deviceRevokedAt != nil {
		return deviceRevoked(ctx)
	}
	return nil
}

// trustOutlivesRevocation reports whether trust stamped at trustedAt still
// stands against the account's last wholesale revocation (revokedAt, written
// by a password change or a disable — User.device_trust_revoked_at). Never
// revoked: it stands. Revoked: only trust stamped strictly LATER stands, so a
// device trusted before the revocation has to pass the second factor again. An
// equal instant (a database that keeps whole seconds) counts as revoked — the
// safe side, at the cost of one extra challenge.
func trustOutlivesRevocation(trustedAt, revokedAt *timestamppb.Timestamp) bool {
	if revokedAt == nil {
		return true
	}
	return trustedAt != nil && trustedAt.AsTime().After(revokedAt.AsTime())
}

// deviceTrustRevokedAt reads when the account's device trust was last revoked
// (nil = never).
func deviceTrustRevokedAt(ctx context.Context, h *AuthServiceHandler, userID string) (*timestamppb.Timestamp, error) {
	resp, err := h.Query.GetDeviceTrustRevokedAt(ctx, &pb.GetDeviceTrustRevokedAtReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return resp.GetDeviceTrustRevokedAt(), nil
}

// neverRevoked is the trust cutoff of an account whose device trust was never
// revoked: any revocation is later than it.
var neverRevoked = timestamppb.New(time.Unix(0, 0))

// deviceLabel is the display half of a device: a friendly label (the
// browser's user agent) and the client address (first X-Forwarded-For hop).
// Neither identifies the device; both are cut to their columns on a rune
// boundary, so a long multi-byte header never becomes invalid UTF-8.
func deviceLabel(ctx context.Context) (label, ip string) {
	md, _ := metadata.FromIncomingContext(ctx)
	ua := firstMeta(md, forwardedUserAgentMetadataKey)
	if ua == "" {
		ua = firstMeta(md, userAgentMetadataKey)
	}
	return truncate(ua, maxLabelLen), truncate(firstHop(firstMeta(md, clientIPMetadataKey)), maxIPLen)
}

// firstMeta returns the first value for a metadata key, or "".
func firstMeta(md metadata.MD, key string) string {
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// firstHop returns the first comma-separated entry of an X-Forwarded-For
// value (the original client), trimmed. Empty stays empty.
func firstHop(xff string) string {
	if i := strings.IndexByte(xff, ','); i >= 0 {
		xff = xff[:i]
	}
	return strings.TrimSpace(xff)
}

// truncate cuts s to at most n bytes without splitting a rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// s[cut] is the first byte left out; while it continues a rune, the cut
	// is inside that rune.
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
