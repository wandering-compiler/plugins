package handlers

import (
	"context"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `devices` feature: the self-service device
// management RPCs (list, revoke one, revoke the others, revoke all). It is
// staged into a bundle ONLY when the activation enables `devices`
// (plugin.yaml go_files). Device identity itself — the Device table, the
// binding of every token to a device key, trust for
// two_factor_scope=new_devices — is base tier and lives in device.go.

// callerDeviceThumbprint is the key thumbprint the caller's token is bound to,
// from the gateway's x-w17-user envelope (Authenticate answers it as
// AuthResp.device_id after checking the request's proof). "" on any miss,
// which the callers read as "this device cannot be pinned".
func callerDeviceThumbprint(ctx context.Context) string {
	var ar pb.AuthResp
	if err := principal.Envelope(ctx, &ar); err != nil {
		return ""
	}
	return ar.GetDeviceId()
}

// ListDevices returns the caller's live devices, deriving `trusted`
// (trusted_at present and later than the account's last trust revocation,
// the same rule the sign-in applies) and `current` (this is the device the
// caller's token is bound to). The key thumbprint never leaves the handler.
func (h *AuthServiceHandler) ListDevices(ctx context.Context, req *pb.ListDevicesReq) (*pb.ListDevicesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListUserDevices(ctx, &pb.ListUserDevicesReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	revokedAt, err := deviceTrustRevokedAt(ctx, h, userID)
	if err != nil {
		return nil, err
	}
	current := callerDeviceThumbprint(ctx)
	out := make([]*pb.DeviceInfo, 0, len(resp.GetDevices()))
	for _, d := range resp.GetDevices() {
		if d.GetThumbprint() == "" {
			// A legacy device (recorded before binding) is history: nothing
			// can sign in with it, so it is not a device to manage. The
			// statement already leaves it out; this keeps it out of the list
			// whatever the store answers.
			continue
		}
		out = append(out, &pb.DeviceInfo{
			Id:         d.GetId(),
			Label:      d.GetLabel(),
			Ip:         d.GetIp(),
			LastSeenAt: d.GetLastSeenAt(),
			Trusted:    d.GetTrustedAt() != nil && trustOutlivesRevocation(d.GetTrustedAt(), revokedAt),
			Current:    current != "" && d.GetThumbprint() == current,
		})
	}
	return &pb.ListDevicesResp{Devices: out}, nil
}

// RevokeDevice revokes one device for good: revoke its tokens, then stamp
// the Device row revoked (never deleted — a deleted row would let the same
// key register again as a fresh device). Both are ownership-guarded by the
// caller's user_id, so a bearer can't revoke another user's device.
// Idempotent.
func (h *AuthServiceHandler) RevokeDevice(ctx context.Context, req *pb.RevokeDeviceReq) (*pb.RevokeDeviceResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := revokeOneDevice(ctx, h, userID, req.GetDeviceId(), noTokenKept); err != nil {
		return nil, err
	}
	return &pb.RevokeDeviceResp{}, nil
}

// RevokeOtherDevices revokes every device except the caller's. The caller's
// device is the one its token is bound to (the envelope's device_id, checked
// against the request's proof by Authenticate); if it matches none of the
// user's devices, every device is revoked — the safe reading of "log out
// everywhere but here" when "here" can't be pinned.
func (h *AuthServiceHandler) RevokeOtherDevices(ctx context.Context, req *pb.RevokeOtherDevicesReq) (*pb.RevokeOtherDevicesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	current := callerDeviceThumbprint(ctx)
	resp, err := h.Query.ListUserDevices(ctx, &pb.ListUserDevicesReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	// "Here" is also the caller's own session: a CLI session whose approving
	// browser is one of the devices revoked here must not be ended with it.
	keep := callerSessionTokenID(ctx)
	if keep == "" {
		keep = noTokenKept
	}
	for _, d := range resp.GetDevices() {
		if current != "" && d.GetThumbprint() == current {
			continue
		}
		if err := revokeOneDevice(ctx, h, userID, d.GetId(), keep); err != nil {
			return nil, err
		}
	}
	if err := revokeUndevicedSessions(ctx, h, userID, callerSessionTokenID(ctx)); err != nil {
		return nil, err
	}
	return &pb.RevokeOtherDevicesResp{}, nil
}

// RevokeAllDevices revokes every device, the caller's included: their
// tokens are revoked and each Device row is stamped revoked, so every key the
// account signed in with must be replaced. Idempotent.
//
// This revokes each device individually via revokeOneDevice
// (RevokeDeviceTokens is device_id-filtered) rather than the broad
// RevokeAllUserTokens, which has no token_type filter (that column is
// api_token-gated) and would ALSO revoke the user's API tokens. Those are
// ended only by RevokeApiToken (or an operator revoking their key on the
// admin Devices page): an API token is bound to a program's key
// (Device.api_key), which ListUserDevices leaves out, and revoking the
// device that created one does not end it (RevokeDeviceTokens' "approved"
// op matches session tokens only). Sessions minted before device binding
// hold no device and are revoked by revokeUndevicedSessions (they no longer
// authenticate either way), still sparing API tokens. Mirrors
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
		if err := revokeOneDevice(ctx, h, userID, d.GetId(), noTokenKept); err != nil {
			return nil, err
		}
	}
	if err := revokeUndevicedSessions(ctx, h, userID, ""); err != nil {
		return nil, err
	}
	return &pb.RevokeAllDevicesResp{}, nil
}

// revokeUndevicedSessions revokes the user's sessions that hold no device, all
// but keep (the caller's own, or none): rows minted before device binding,
// reason UNBOUND_SESSION. They no longer authenticate (Authenticate refuses an
// unbound token), so this records their end rather than causes it. Sessions
// bound to a LEGACY device (a pre-binding Device row, no key) carry a
// device_id and are not matched here; they are refused at authentication all
// the same, as bound to no key.
func revokeUndevicedSessions(ctx context.Context, h *AuthServiceHandler, userID, keep string) error {
	if keep == "" {
		keep = noTokenKept
	}
	_, err := h.Mutation.RevokeUndevicedSessions(ctx, &pb.RevokeUndevicedSessionsReq{UserId: userID, KeepTokenId: keep})
	return notFoundOK(err)
}

// revokeOneDevice revokes a device's tokens (reason DEVICE_REVOKED) then
// stamps the Device row revoked, both guarded by user_id; nothing is deleted.
// Tokens first, so a partial failure leaves a live, listed device to retry on;
// the device's revocation alone would refuse them too (Authenticate reads it
// through the token's binding). An already revoked device matches no row
// (NotFound), which is done, not a failure.
//
// RevokeDeviceTokens also ends the CLI sessions the device approved, all but
// keep (the caller's own session for RevokeOtherDevices, else noTokenKept).
func revokeOneDevice(ctx context.Context, h *AuthServiceHandler, userID, deviceID, keep string) error {
	if _, err := h.Mutation.RevokeDeviceTokens(ctx, &pb.RevokeDeviceTokensReq{UserId: userID, DeviceId: deviceID, RevokedBy: userID, KeepTokenId: keep}); notFoundOK(err) != nil {
		return err
	}
	if _, err := h.Mutation.MarkDeviceRevoked(ctx, &pb.MarkDeviceRevokedReq{UserId: userID, DeviceId: deviceID}); notFoundOK(err) != nil {
		return err
	}
	return nil
}
