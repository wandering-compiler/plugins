package handlers

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// deviceMock records what the `devices` management RPCs called.
type deviceMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	listResult []*pb.Device

	deletedTokens []*pb.DeleteDeviceTokensReq
	revokedDevs   []*pb.MarkDeviceRevokedReq
	allTokensFor  string
	undeviced     []*pb.DeleteUndevicedSessionsReq

	// User.device_trust_revoked_at, and a read failure for it
	revokedAt  *timestamppb.Timestamp
	revokedErr error
}

func (m *deviceMock) GetDeviceTrustRevokedAt(context.Context, *pb.GetDeviceTrustRevokedAtReq, ...grpc.CallOption) (*pb.GetDeviceTrustRevokedAtResp, error) {
	if m.revokedErr != nil {
		return nil, m.revokedErr
	}
	return &pb.GetDeviceTrustRevokedAtResp{DeviceTrustRevokedAt: m.revokedAt}, nil
}

func (m *deviceMock) ListUserDevices(context.Context, *pb.ListUserDevicesReq, ...grpc.CallOption) (*pb.ListUserDevicesResp, error) {
	return &pb.ListUserDevicesResp{Devices: m.listResult}, nil
}

func (m *deviceMock) DeleteUndevicedSessions(_ context.Context, in *pb.DeleteUndevicedSessionsReq, _ ...grpc.CallOption) (*pb.DeleteUndevicedSessionsResp, error) {
	m.undeviced = append(m.undeviced, in)
	return &pb.DeleteUndevicedSessionsResp{UserId: in.GetUserId()}, nil
}

func (m *deviceMock) DeleteDeviceTokens(_ context.Context, in *pb.DeleteDeviceTokensReq, _ ...grpc.CallOption) (*pb.DeleteDeviceTokensResp, error) {
	m.deletedTokens = append(m.deletedTokens, in)
	return &pb.DeleteDeviceTokensResp{DeviceId: in.GetDeviceId()}, nil
}

func (m *deviceMock) MarkDeviceRevoked(_ context.Context, in *pb.MarkDeviceRevokedReq, _ ...grpc.CallOption) (*pb.MarkDeviceRevokedResp, error) {
	m.revokedDevs = append(m.revokedDevs, in)
	return &pb.MarkDeviceRevokedResp{DeviceId: in.GetDeviceId()}, nil
}

func (m *deviceMock) DeleteAllUserTokens(_ context.Context, in *pb.DeleteAllUserTokensReq, _ ...grpc.CallOption) (*pb.DeleteAllUserTokensResp, error) {
	m.allTokensFor = in.GetUserId()
	return &pb.DeleteAllUserTokensResp{UserId: in.GetUserId()}, nil
}

// ctxOnDevice is a management request from uid whose token is bound to the
// key jkt: the envelope Authenticate answered (device_id) as the gateway
// forwards it, plus the session the token resolved to.
func ctxOnDevice(t *testing.T, uid, sessionID, jkt string) context.Context {
	t.Helper()
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: sessionID, DeviceId: jkt})
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid, userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// `current` is the device the caller's token is bound to (the envelope's
// device_id), never anything the request names; the thumbprint is not
// listed.
func TestListDevices_MarksTrustedAndCurrent(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{
		{Id: "dev-cur", Thumbprint: testJKT, Label: "Phone", TrustedAt: timestamppb.Now()},
		{Id: "dev-other", Thumbprint: otherJKT, Label: "Laptop"},
		// legacy: recorded before binding, no key — history, not listed
		{Id: "dev-legacy", Label: "Old browser", TrustedAt: timestamppb.Now()},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.ListDevicesReq{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetDevices()) != 2 {
		t.Fatalf("want 2 devices, got %d", len(resp.GetDevices()))
	}
	cur, other := resp.GetDevices()[0], resp.GetDevices()[1]
	if !cur.GetCurrent() || !cur.GetTrusted() {
		t.Errorf("dev-cur should be current+trusted, got %+v", cur)
	}
	if other.GetCurrent() || other.GetTrusted() {
		t.Errorf("dev-other should be neither current nor trusted, got %+v", other)
	}
	// An envelope with no device pins nothing as current.
	resp, err = h.ListDevices(ctxOnDevice(t, "u1", "s1", ""), &pb.ListDevicesReq{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.GetDevices() {
		if d.GetCurrent() {
			t.Errorf("%s marked current with no device in the envelope", d.GetId())
		}
	}
}

func TestListDevices_NoCaller_Unauthenticated(t *testing.T) {
	h := &AuthServiceHandler{Query: &deviceMock{}, Mutation: &deviceMock{}}
	if _, err := h.ListDevices(context.Background(), &pb.ListDevicesReq{}); err == nil {
		t.Fatal("expected Unauthenticated without caller scope")
	}
}

// ListDevices applies the sign-in's rule: a device trusted before the
// account's last revocation is listed as untrusted. A revocation that cannot
// be read fails the list rather than guessing.
func TestListDevices_TrustRevokedByACredentialChange_NotShownTrusted(t *testing.T) {
	m := &deviceMock{
		listResult: []*pb.Device{
			{Id: "dev-old", Thumbprint: testJKT, TrustedAt: timestamppb.New(time.Now().Add(-2 * time.Hour))},
			{Id: "dev-new", Thumbprint: otherJKT, TrustedAt: timestamppb.Now()},
		},
		revokedAt: timestamppb.New(time.Now().Add(-time.Hour)),
	}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.ListDevicesReq{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := resp.GetDevices(); len(got) != 2 || got[0].GetTrusted() || !got[1].GetTrusted() {
		t.Errorf("want dev-old untrusted (trusted before the revocation) and dev-new trusted, got %+v", got)
	}
	m.revokedErr = status.Error(codes.Unavailable, "db down")
	if _, err := h.ListDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.ListDevicesReq{}); status.Code(err) != codes.Unavailable {
		t.Errorf("an unreadable revocation must fail the list, got %v", err)
	}
}

// device/revocation-is-a-state: revoking a device deletes its tokens and
// stamps the row revoked — never deletes it, so the key cannot come back as a
// fresh device. Both writes carry the caller's user_id guard.
func TestRevokeDevice_DeletesTokensThenMarksTheDeviceRevoked(t *testing.T) {
	m := &deviceMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeDevice(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeDeviceReq{DeviceId: "dev-7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(m.deletedTokens) != 1 || m.deletedTokens[0].GetUserId() != "u1" || m.deletedTokens[0].GetDeviceId() != "dev-7" {
		t.Errorf("token delete guard wrong: %+v", m.deletedTokens)
	}
	if len(m.revokedDevs) != 1 || m.revokedDevs[0].GetUserId() != "u1" || m.revokedDevs[0].GetDeviceId() != "dev-7" {
		t.Errorf("device revocation wrong: %+v", m.revokedDevs)
	}
}

// "Here" is the device the caller's token is bound to.
func TestRevokeOtherDevices_KeepsTheCallersDevice(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{
		{Id: "dev-cur", Thumbprint: testJKT},
		{Id: "dev-a", Thumbprint: otherJKT},
		{Id: "dev-b", Thumbprint: "b" + testJKT[1:]},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeOtherDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatalf("revoke-others: %v", err)
	}
	if len(m.revokedDevs) != 2 {
		t.Fatalf("want 2 devices revoked (not the current), got %+v", m.revokedDevs)
	}
	for _, d := range m.revokedDevs {
		if d.GetDeviceId() == "dev-cur" {
			t.Error("must not revoke the current device")
		}
	}
	// No device in the envelope: "here" cannot be pinned, so everything goes.
	m.revokedDevs = nil
	if _, err := h.RevokeOtherDevices(ctxOnDevice(t, "u1", "s1", ""), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	if len(m.revokedDevs) != 3 {
		t.Fatalf("an unpinned caller kept a device: %+v", m.revokedDevs)
	}
}

// RevokeAllDevices revokes each device individually — NOT the broad
// DeleteAllUserTokens, which has no token_type filter and would also delete
// the user's API tokens.
func TestRevokeAllDevices_PerDeviceSparesApiTokens(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{{Id: "dev-1"}, {Id: "dev-2"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeAllDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if m.allTokensFor != "" {
		t.Errorf("revoke-all must NOT call DeleteAllUserTokens (it deletes API tokens too); got %q", m.allTokensFor)
	}
	if len(m.deletedTokens) != 2 || len(m.revokedDevs) != 2 {
		t.Errorf("revoke-all must delete tokens + revoke per device (2 each); got %d token-deletes, %d revocations",
			len(m.deletedTokens), len(m.revokedDevs))
	}
}

// notFoundMock answers NotFound from every revoke write, so the RPCs must
// treat it as done (an already revoked device matches no row).
type notFoundMock struct{ deviceMock }

func (notFoundMock) DeleteDeviceTokens(context.Context, *pb.DeleteDeviceTokensReq, ...grpc.CallOption) (*pb.DeleteDeviceTokensResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) MarkDeviceRevoked(context.Context, *pb.MarkDeviceRevokedReq, ...grpc.CallOption) (*pb.MarkDeviceRevokedResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) DeleteUndevicedSessions(context.Context, *pb.DeleteUndevicedSessionsReq, ...grpc.CallOption) (*pb.DeleteUndevicedSessionsResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}

func TestRevokeDevice_IdempotentOnMissing(t *testing.T) {
	m := &notFoundMock{deviceMock{listResult: []*pb.Device{{Id: "dev-1"}}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeDevice(ctxWithCaller("u1"), &pb.RevokeDeviceReq{DeviceId: "ghost"}); err != nil {
		t.Errorf("revoking a missing or already revoked device must be a no-op, got %v", err)
	}
	if _, err := h.RevokeAllDevices(ctxWithCaller("u1"), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Errorf("revoke-all over revoked devices must be a no-op, got %v", err)
	}
}

// Sessions minted before device binding hold no device; "log out everywhere"
// sweeps them too, keeping none, and "log out the others" keeps only the
// caller's own session.
func TestRevokeDevices_SweepSessionsNoDeviceHolds(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{{Id: "dev-a", Thumbprint: otherJKT}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeAllDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	if len(m.undeviced) != 1 || m.undeviced[0].GetUserId() != "u1" || m.undeviced[0].GetKeepTokenId() != noTokenKept {
		t.Fatalf("revoke-all: device-less sessions not swept, keeping none: %+v", m.undeviced)
	}
	m.undeviced = nil
	if _, err := h.RevokeOtherDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	if len(m.undeviced) != 1 || m.undeviced[0].GetUserId() != "u1" || m.undeviced[0].GetKeepTokenId() != "s1" {
		t.Fatalf("revoke-others: device-less sessions not swept keeping the caller's: %+v", m.undeviced)
	}
	nf := &notFoundMock{}
	hn := &AuthServiceHandler{Query: nf, Mutation: nf}
	if _, err := hn.RevokeAllDevices(ctxOnDevice(t, "u1", "s1", testJKT), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatalf("an empty sweep must not fail revoke-all: %v", err)
	}
}
