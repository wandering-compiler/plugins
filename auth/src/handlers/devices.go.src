package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `devices` feature. It is staged into a bundle
// ONLY when the activation enables `devices` (plugin.yaml maps the feature
// to this file via go_files). With the feature off it is not staged, so
// the sign-in seams keep their defaults (no device tracking) and the
// UserToken.device_id column / Device table aren't emitted. Standalone
// (the plugin author's own `go test`) always compiles it, since gating
// happens at activation staging, not in the source tree.

// Device-detection metadata keys. The gateway lowercases forwarded header
// names into gRPC metadata (MetadataPropagation); a project enables device
// tracking by forwarding these via `(w17.rest_api).metadata_propagation`
// (X-Device-Id + User-Agent + X-Forwarded-For). Absent header →
// fingerprint fallback, so a misconfigured project still tracks devices
// coarsely rather than crashing.
const (
	deviceIDMetadataKey    = "x-device-id"     // stable client-managed device id
	deviceTrustMetadataKey = "x-device-trust"  // C2: server-issued device-trust token (replayed by the client)
	userAgentMetadataKey   = "user-agent"      // → Device.label (friendly name)
	clientIPMetadataKey    = "x-forwarded-for" // → Device.ip (first hop)
)

const (
	maxIdentifierLen = 128 // Device.identifier CHAR(128)
	maxLabelLen      = 255 // Device.label CHAR(255)
)

// init wires the devices behaviour on package load: the sign-in device
// resolver (upsert + trusted signal) AND the device-bound token issuer
// (issues the session bound to the device, plus trust). The
// bundle imports this package (alias-imported under the activation name),
// so init runs once during server bring-up.
func init() {
	resolveSignInDevice = resolveSignInDeviceImpl
	issueSession = issueSessionWithDevice
	// `device_trust_token` exists on SignInResp only when `devices` is active
	// (this file is staged) — so the field reference is safe to compile here.
	stampSignInDeviceTrust = func(resp *pb.SignInResp, trustToken string) {
		resp.DeviceTrustToken = trustToken
	}
	// The message-gated responses (OAuthCallbackResp / VerifyMfaResp) carry the
	// same `device_trust_token`, but their Go type isn't compiled unless their
	// own feature is active — so set it by proto NAME via reflection instead of
	// naming the field. No-op for a message that lacks the field.
	stampDeviceTrust = func(msg proto.Message, trustToken string) {
		m := msg.ProtoReflect()
		if fd := m.Descriptor().Fields().ByName("device_trust_token"); fd != nil {
			m.Set(fd, protoreflect.ValueOfString(trustToken))
		}
	}
	devicesActive = true // lets ValidateConfig allow two_factor_scope=new_devices
}

// deviceIdentity is the resolved device coordinates for the current
// request: a stable identifier (header or fingerprint), a friendly label
// (user-agent), the client IP, and the C2 server-issued device-trust
// token the client replays (empty if none).
type deviceIdentity struct {
	identifier string
	label      string
	ip         string
	trustToken string
}

// resolveDeviceIdentity derives the request's device coordinates from
// incoming gRPC metadata. Prefers the client-sent X-Device-Id (stable
// across token rotation); falls back to a SHA-256 fingerprint of
// user-agent + IP. The fingerprint is best-effort: UA/IP churn yields a
// new identifier → a new-device read → (under two_factor new-device mode)
// an extra challenge, which is the safe failure, never fail-open. The
// X-Device-Trust token (C2) is read straight through — it proves device
// trust, distinct from the X-Device-Id which only names the device.
func resolveDeviceIdentity(ctx context.Context) deviceIdentity {
	md, _ := metadata.FromIncomingContext(ctx)
	ua := firstMeta(md, userAgentMetadataKey)
	ip := firstHop(firstMeta(md, clientIPMetadataKey))

	di := deviceIdentity{
		label:      truncate(ua, maxLabelLen),
		ip:         ip,
		trustToken: strings.TrimSpace(firstMeta(md, deviceTrustMetadataKey)),
	}
	if hdr := strings.TrimSpace(firstMeta(md, deviceIDMetadataKey)); hdr != "" {
		di.identifier = truncate(hdr, maxIdentifierLen)
		return di
	}
	sum := sha256.Sum256([]byte(ua + "|" + ip))
	di.identifier = hex.EncodeToString(sum[:]) // 64 hex chars, fits CHAR(128)
	return di
}

// newDeviceTrustToken mints a fresh high-entropy device-trust token: the
// plaintext to hand back to the client and its SHA-256 hex to store on the
// Device row. The plaintext is never persisted — a DB read can't
// impersonate a trusted device. (C2)
func newDeviceTrustToken() (token, hash string, err error) {
	b := make([]byte, 32) // 256-bit
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashDeviceTrustToken(token), nil
}

// hashDeviceTrustToken is the one-way function applied to a device-trust
// token for storage + comparison (SHA-256 hex, fits CHAR(128)).
func hashDeviceTrustToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// deviceTrustValid reports whether the presented trust token proves the
// device is trusted: the row must carry a stored hash AND the presented
// token must hash to it (constant-time). A device with trusted_at but no
// stored hash (e.g. a pre-C2 row) or a request with no/empty token is NOT
// trusted — the safe direction, costing at most one extra new-device
// challenge after which a fresh token is minted. (C2)
func deviceTrustValid(dev *pb.Device, presented string) bool {
	stored := dev.GetTrustTokenHash()
	if stored == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashDeviceTrustToken(presented)), []byte(stored)) == 1
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
	if xff == "" {
		return ""
	}
	if i := strings.IndexByte(xff, ','); i >= 0 {
		return strings.TrimSpace(xff[:i])
	}
	return strings.TrimSpace(xff)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// resolveSignInDeviceImpl resolves (and upserts) the device this sign-in
// belongs to, returning its id + whether it is already trusted. First
// sight of an (user, identifier) creates the Device (trusted_at NULL);
// the unique index makes a racing duplicate surface as an error on
// CreateDevice, which we recover from by re-reading. Any GetDevice error
// is treated as "not seen yet" and falls through to create.
func resolveSignInDeviceImpl(ctx context.Context, h *AuthServiceHandler, userID string) (string, bool, error) {
	di := resolveDeviceIdentity(ctx)

	if dev := getDevice(ctx, h, userID, di.identifier); dev != nil {
		// C2 — trust requires proving possession of the server-issued
		// trust token, not merely a trusted_at flag on a client-named
		// device (which an attacker who learns the victim's X-Device-Id
		// could otherwise ride to skip new-device 2FA).
		return dev.GetId(), deviceTrustValid(dev, di.trustToken), nil
	}
	created, err := h.Mutation.CreateDevice(ctx, &pb.CreateDeviceReq{
		UserId:     userID,
		Identifier: di.identifier,
		Label:      di.label,
		Ip:         di.ip,
	})
	if err != nil {
		// Likely a concurrent create (unique violation) — re-read.
		if dev := getDevice(ctx, h, userID, di.identifier); dev != nil {
			return dev.GetId(), deviceTrustValid(dev, di.trustToken), nil
		}
		return "", false, err
	}
	// A freshly-created device has no stored trust hash → untrusted.
	dev := created.GetDevice()
	return dev.GetId(), deviceTrustValid(dev, di.trustToken), nil
}

// getDevice reads the (user, identifier) device, returning nil on any
// miss (NotFound or transient) so callers fall through to create.
func getDevice(ctx context.Context, h *AuthServiceHandler, userID, identifier string) *pb.Device {
	resp, err := h.Query.GetDeviceByIdentifier(ctx, &pb.GetDeviceByIdentifierReq{
		UserId:     userID,
		Identifier: identifier,
	})
	if err != nil {
		return nil
	}
	return resp.GetDevice()
}

// issueSessionWithDevice mints a device-bound session token and trusts the
// device (a completed login means this device passed every gate). C2: it
// also mints a fresh device-trust token, stores its hash on the row, and
// returns the plaintext for the caller to hand back to the client (which
// replays it as X-Device-Trust to skip the next new-device challenge).
// Trust is best-effort: a failed TrustDevice / token mint doesn't
// invalidate the freshly issued session, so the error is swallowed and the
// returned trust token is empty (the device simply re-challenges next
// new-device sign-in — fail-safe). The token is rotated every login.
func issueSessionWithDevice(ctx context.Context, h *AuthServiceHandler, userID, deviceID string) (string, string, error) {
	tok, err := h.Mutation.IssueToken(ctx, &pb.IssueTokenReq{
		UserId:    userID,
		DeviceId:  deviceID,
		ExpiresAt: h.sessionTokenExpiry(),
	})
	if err != nil {
		return "", "", err
	}
	var trustToken string
	if deviceID != "" {
		if plain, hash, gErr := newDeviceTrustToken(); gErr == nil {
			if _, tErr := h.Mutation.TrustDevice(ctx, &pb.TrustDeviceReq{
				UserId:         userID,
				DeviceId:       deviceID,
				TrustTokenHash: hash,
			}); tErr == nil {
				trustToken = plain
			}
		}
	}
	return tok.GetToken().GetToken(), trustToken, nil
}

// ListDevices returns the caller's devices, deriving `trusted`
// (trusted_at present) and `current` (this device matches the calling
// request's resolved identifier). The raw identifier never leaves the
// handler.
func (h *AuthServiceHandler) ListDevices(ctx context.Context, req *pb.ListDevicesReq) (*pb.ListDevicesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListUserDevices(ctx, &pb.ListUserDevicesReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	current := resolveDeviceIdentity(ctx).identifier
	out := make([]*pb.DeviceInfo, 0, len(resp.GetDevices()))
	for _, d := range resp.GetDevices() {
		out = append(out, &pb.DeviceInfo{
			Id:         d.GetId(),
			Label:      d.GetLabel(),
			Ip:         d.GetIp(),
			LastSeenAt: d.GetLastSeenAt(),
			Trusted:    d.GetTrustedAt() != nil,
			Current:    d.GetIdentifier() == current,
		})
	}
	return &pb.ListDevicesResp{Devices: out}, nil
}

// RevokeDevice logs out one device: delete its tokens, then the Device
// row. Both are ownership-guarded by the caller's user_id, so a bearer
// can't revoke another user's device. Idempotent.
func (h *AuthServiceHandler) RevokeDevice(ctx context.Context, req *pb.RevokeDeviceReq) (*pb.RevokeDeviceResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := revokeOneDevice(ctx, h, userID, req.GetDeviceId()); err != nil {
		return nil, err
	}
	return &pb.RevokeDeviceResp{}, nil
}

// RevokeOtherDevices logs out every device except the caller's. The
// caller's device is identified by the calling request's resolved
// identifier; if it matches none of the user's devices (e.g. a
// fingerprint that has drifted), every device is revoked — the safe
// reading of "log out everywhere but here" when "here" can't be pinned.
func (h *AuthServiceHandler) RevokeOtherDevices(ctx context.Context, req *pb.RevokeOtherDevicesReq) (*pb.RevokeOtherDevicesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	current := resolveDeviceIdentity(ctx).identifier
	resp, err := h.Query.ListUserDevices(ctx, &pb.ListUserDevicesReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	for _, d := range resp.GetDevices() {
		if d.GetIdentifier() == current {
			continue
		}
		if err := revokeOneDevice(ctx, h, userID, d.GetId()); err != nil {
			return nil, err
		}
	}
	return &pb.RevokeOtherDevicesResp{}, nil
}

// RevokeAllDevices logs out everywhere (including the caller): revoke every
// device's tokens + Device row. Idempotent.
//
// B22-auth-2: this revokes each device individually via revokeOneDevice
// (DeleteDeviceTokens is device_id-filtered) rather than the broad
// DeleteAllUserTokens. DeleteAllUserTokens has no token_type filter (that
// column is api_token-gated, Q64-auth-1), so it would ALSO delete the user's
// API tokens — credentials that aren't device-bound (device_id NULL) and must
// only be removed via RevokeApiToken. Every interactive session is device-bound
// (the devices feature stamps device_id on the issued token), so the
// per-device sweep covers all sessions while sparing API tokens. Mirrors
// RevokeOtherDevices, but includes the caller's current device.
func (h *AuthServiceHandler) RevokeAllDevices(ctx context.Context, req *pb.RevokeAllDevicesReq) (*pb.RevokeAllDevicesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListUserDevices(ctx, &pb.ListUserDevicesReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	for _, d := range resp.GetDevices() {
		if err := revokeOneDevice(ctx, h, userID, d.GetId()); err != nil {
			return nil, err
		}
	}
	return &pb.RevokeAllDevicesResp{}, nil
}

// revokeOneDevice deletes a device's tokens then the Device row, both
// guarded by user_id. Token delete first so a partial failure leaves the
// Device (and its now-orphaned membership) discoverable for retry rather
// than a dangling token with no Device.
func revokeOneDevice(ctx context.Context, h *AuthServiceHandler, userID, deviceID string) error {
	if _, err := h.Mutation.DeleteDeviceTokens(ctx, &pb.DeleteDeviceTokensReq{UserId: userID, DeviceId: deviceID}); notFoundOK(err) != nil {
		return err
	}
	if _, err := h.Mutation.DeleteDevice(ctx, &pb.DeleteDeviceReq{UserId: userID, DeviceId: deviceID}); notFoundOK(err) != nil {
		return err
	}
	return nil
}
