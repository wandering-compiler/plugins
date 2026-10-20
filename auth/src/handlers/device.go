package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/principal"

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
//     AuthResp.device_id. The MCP surface, whose clients cannot sign yet, is
//     the one exception: marked `x-w17-surface: mcp` by its gateway, it may
//     present an mcp_only token without a proof (checkMCPToken).
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

	// surfaceKey / surfaceMCP mark a request the MCP gateway authenticates:
	// gateway-owned (x-w17-*, stripped from client input), set only by the
	// MCP surface, whose clients keep the OAuth 2.1 flow without DPoP. With
	// it, a proofless request may present an mcp_only token.
	surfaceKey = "x-w17-surface"
	surfaceMCP = "mcp"
	// mcpResourceKey is the OAuth resource the MCP surface serves, stamped
	// by the gateway on a surface that is a protected resource
	// (principal.MCPResourceKey).
	mcpResourceKey = "x-w17-mcp-resource"

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

// signInDevice is what mintDevice found: the device's id and key
// thumbprint, whether it is trusted, and — for a trusted one — the cutoff a
// renewal of that trust must hold against (see issueSession's trustCutoff).
type signInDevice struct {
	id          string
	thumbprint  string
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
//
// A revoked device comes back with its id beside the refusal, for the
// sign-in history (no token is ever bound to it).
//
// A PROGRAM's key (Device.api_key: named for an API token) is refused too,
// with the opaque refusal: a program key never signs in. Otherwise a session
// could live on a device the owner's device management does not list, and
// "sign out everywhere else" would leave it running.
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
		return signInDevice{id: dev.GetId(), thumbprint: thumbprint}, deviceRevoked(ctx)
	}
	if dev.GetApiKey() {
		return signInDevice{id: dev.GetId(), thumbprint: thumbprint}, errDeviceIsAProgramKey
	}
	out := signInDevice{id: dev.GetId(), thumbprint: thumbprint}
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

// revokeApprovedAPITokens revokes the owner's API tokens the device created
// (UserToken.approved_by_device_id), on ctx. Installed by apitoken.go: nil
// without api_token, where no API token exists. Called only when ONE device
// is revoked on purpose (the owner's RevokeDevice, the admin RevokeDevices);
// RevokeOtherDevices and RevokeAllDevices spare API tokens.
var revokeApprovedAPITokens func(ctx context.Context, h *AuthServiceHandler, userID, deviceID, revokedBy string) error

// endApprovedAPITokens runs revokeApprovedAPITokens when it is installed.
func endApprovedAPITokens(ctx context.Context, h *AuthServiceHandler, userID, deviceID, revokedBy string) error {
	if revokeApprovedAPITokens == nil {
		return nil
	}
	return revokeApprovedAPITokens(ctx, h, userID, deviceID, revokedBy)
}

// noTokenKept is the keep_token_id that keeps none (the column is a UUID, so
// the empty string would not bind). Base tier: the devices calls and the admin
// Devices page both pass it to RevokeDeviceTokens.
const noTokenKept = "00000000-0000-0000-0000-000000000000"

// sessionGrant is what a mint records on the session beside its device:
// whether it is a public-computer session, and — for a CLI session — the
// Device row of the browser session that approved it.
type sessionGrant struct {
	public     bool
	approvedBy string
}

// issueBoundToken mints a session token bound to dev, expiring at
// expiresAt, and returns the token the caller is handed once. The ONE place a
// session row is written, so there is no path that mints one unbound:
// IssueToken's request requires the device as well. The device's key
// thumbprint goes to TokenIssued as its device_id.
func (h *AuthServiceHandler) issueBoundToken(ctx context.Context, userID string, dev signInDevice, expiresAt *timestamppb.Timestamp, grant sessionGrant) (string, error) {
	if dev.id == "" {
		return "", errDeviceNotRegistered
	}
	token, hash, err := newBearerToken()
	if err != nil {
		return "", err
	}
	if _, err := h.Mutation.IssueToken(ctx, &pb.IssueTokenReq{
		UserId:     userID,
		DeviceId:   dev.id,
		ExpiresAt:  expiresAt,
		TokenHash:  hash,
		Thumbprint: dev.thumbprint,

		PublicComputer:     grant.public,
		ApprovedByDeviceId: grant.approvedBy,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// issueSession mints the session bearer for an authenticated principal,
// bound to the device mintDevice registered, with the session lifetime — the
// public-computer one when the attempt asked for it — and writes the
// attempt's success row with it (mintSession: one transaction). Shared by
// SignIn, VerifyMfa and the OAuth exchange.
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
// A public-computer sign-in never trusts the device, whatever cutoff it
// brings: the next person at that computer must meet the second factor again.
//
// Trust is best effort: a failed TrustDevice leaves the device untrusted (it
// is challenged again next time) and does not fail the session just issued.
// It is written after the session's transaction commits, so a failed trust
// statement cannot abort that transaction.
func issueSession(ctx context.Context, h *AuthServiceHandler, a *signInAttempt, userID string, dev signInDevice, trustCutoff *timestamppb.Timestamp) (string, error) {
	token, err := h.mintSession(ctx, a, userID, dev, h.sessionExpiry(a.publicComputer), "")
	if err != nil {
		return "", err
	}
	if trustCutoff != nil && !a.publicComputer {
		_, _ = h.Mutation.TrustDevice(ctx, &pb.TrustDeviceReq{
			UserId:          userID,
			DeviceId:        dev.id,
			NotRevokedAfter: trustCutoff,
		})
	}
	return token, nil
}

// requestThumbprint is the key thumbprint of the device the current request
// comes from, for the device_id of the events it causes: on an authenticated
// request the envelope's device (Authenticate matched the proof to the
// token's binding), on a mint request the proof's key. Empty when there is
// neither (project code calling a handler directly).
func requestThumbprint(ctx context.Context) string {
	var ar pb.AuthResp
	if err := principal.Envelope(ctx, &ar); err == nil && ar.GetDeviceId() != "" {
		return ar.GetDeviceId()
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if jkt := firstMeta(md, dpopJKTKey); validThumbprint(jkt) {
		return jkt
	}
	return ""
}

// checkTokenBinding is Authenticate's device check for a request that proved
// a key (jkt, the thumbprint the gateway verified), run once the token has
// resolved. What each answer may say decides the order:
//
//   - a token bound to no device (minted before device binding, or an MCP
//     token) and a token bound to another key are the OPAQUE refusal — the
//     same answer an unknown token gets, so whoever holds a stolen token but
//     not its key learns nothing: not that it is live, not when it is
//     revoked;
//   - only the holder of the bound key learns DEVICE_REVOKED, which tells
//     its client to generate a new key.
//
// A request that proved no key never gets here: Authenticate refuses it with
// DEVICE_PROOF_REQUIRED before looking the token up (or, on the MCP surface,
// sends it to checkMCPToken).
func checkTokenBinding(ctx context.Context, p *authPrincipal, jkt string) error {
	if p.deviceThumbprint == "" || !sameKey(p.deviceThumbprint, jkt) {
		return errDeviceBindingRefused
	}
	if p.deviceRevokedAt != nil {
		return deviceRevoked(ctx)
	}
	return nil
}

// checkMCPToken is the check for a proofless request on the MCP surface: only
// a token of the MCP OAuth flow passes (mcp_only), bound to no device, and
// only on the resource it was issued for (RFC 8707: served is the resource the
// gateway names). A token issued for one resource is refused on another and on
// a surface that names none; a surface that names one refuses a token issued
// for none. Any other token is the opaque refusal, like an unknown one.
func checkMCPToken(p *authPrincipal, served string) error {
	if !p.mcpOnly {
		return errDeviceBindingRefused
	}
	if normalizeResource(p.oauthResource) != normalizeResource(served) {
		return errMCPResourceMismatch
	}
	return nil
}

// normalizeResource is the comparable form of a resource identifier (RFC
// 8707): scheme and host lower-cased, a default port dropped, a trailing
// slash dropped — so `https://MCP.example.com:443/mcp/` and
// `https://mcp.example.com/mcp` name one resource and a client that spells
// it the other way does not loop on 401s. Anything unparsable is compared as
// written.
func normalizeResource(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	u.Host = host
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String()
}

// errMCPResourceMismatch is the cause behind the opaque refusal of an MCP
// token on a resource it was not issued for. Never on the wire.
var errMCPResourceMismatch = errors.New("the MCP token was issued for another resource")

// checkBotBearer is the check for a proofless request presenting a token with
// the bot-bearer prefix (device/bot-bearer): only a token the row flags
// `bearer`, of an API token owned by a machine account and bound to no
// device, passes. Anything else — a person's token, a bound bot token, an MCP
// token, a legacy unbound row — is the opaque refusal, like an unknown one:
// the prefix authorizes nothing.
func checkBotBearer(p *authPrincipal) error {
	if !p.bearer || !p.botAccount || p.realm != pb.TokenType_TOKEN_TYPE_API || p.deviceThumbprint != "" || p.mcpOnly {
		return errDeviceBindingRefused
	}
	return nil
}

// sameKey compares two thumbprints in constant time.
func sameKey(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// errDeviceIsAProgramKey is the cause behind the refusal of a sign-in whose
// proof is by a program's key (Device.api_key). Never on the wire: the
// opaque refusal.
var errDeviceIsAProgramKey = errors.New("the key is a program's key (an API token's device); it does not sign in")

// errDeviceBindingRefused is the cause behind the opaque refusal of a token
// the request's proof does not match (or a non-MCP token without a proof on
// the MCP surface). Never on the wire: it reads as "invalid credentials".
var errDeviceBindingRefused = errors.New("token not bound to the request's device key")

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
// Neither identifies the device; both are made valid UTF-8 and cut to their
// columns on a rune boundary, so no header becomes invalid UTF-8 at rest.
func deviceLabel(ctx context.Context) (label, ip string) {
	md, _ := metadata.FromIncomingContext(ctx)
	ua := firstMeta(md, forwardedUserAgentMetadataKey)
	if ua == "" {
		ua = firstMeta(md, userAgentMetadataKey)
	}
	// Valid UTF-8 first: a header may carry any bytes, and the columns (and
	// the sign-in history's) are text.
	return truncate(strings.ToValidUTF8(ua, invalidUTF8), maxLabelLen),
		truncate(strings.ToValidUTF8(firstHop(firstMeta(md, clientIPMetadataKey)), invalidUTF8), maxIPLen)
}

// invalidUTF8 replaces a byte that is not UTF-8 in a value kept as text: the
// replacement character, so the byte stays visible as a bad one.
const invalidUTF8 = "\uFFFD"

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
