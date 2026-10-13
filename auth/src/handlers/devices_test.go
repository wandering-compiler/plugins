package handlers

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// deviceMock satisfies both client interfaces (embedded nil) and records
// what the device handlers / sign-in seams called.
type deviceMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	// query state
	getByIdent map[string]*pb.Device // key user|identifier -> device (nil = not found)
	listResult []*pb.Device

	// recorded calls
	created       []*pb.CreateDeviceReq
	issuedWith    []*pb.IssueTokenReq
	trusted       []*pb.TrustDeviceReq
	deletedTokens []*pb.DeleteDeviceTokensReq
	deletedDevs   []*pb.DeleteDeviceReq
	allTokensFor  string
	allDevsFor    string
	undeviced     []*pb.DeleteUndevicedSessionsReq

	// User.device_trust_revoked_at, and a read failure for it
	revokedAt  *timestamppb.Timestamp
	revokedErr error
	revokeRead int
}

func (m *deviceMock) GetDeviceTrustRevokedAt(ctx context.Context, in *pb.GetDeviceTrustRevokedAtReq, _ ...grpc.CallOption) (*pb.GetDeviceTrustRevokedAtResp, error) {
	m.revokeRead++
	if m.revokedErr != nil {
		return nil, m.revokedErr
	}
	return &pb.GetDeviceTrustRevokedAtResp{DeviceTrustRevokedAt: m.revokedAt}, nil
}

func (m *deviceMock) DeleteUndevicedSessions(ctx context.Context, in *pb.DeleteUndevicedSessionsReq, _ ...grpc.CallOption) (*pb.DeleteUndevicedSessionsResp, error) {
	m.undeviced = append(m.undeviced, in)
	return &pb.DeleteUndevicedSessionsResp{UserId: in.GetUserId()}, nil
}

func devKey(user, ident string) string { return user + "|" + ident }

func (m *deviceMock) GetDeviceByIdentifier(ctx context.Context, in *pb.GetDeviceByIdentifierReq, _ ...grpc.CallOption) (*pb.GetDeviceByIdentifierResp, error) {
	d := m.getByIdent[devKey(in.GetUserId(), in.GetIdentifier())]
	return &pb.GetDeviceByIdentifierResp{Device: d}, nil
}
func (m *deviceMock) ListUserDevices(ctx context.Context, in *pb.ListUserDevicesReq, _ ...grpc.CallOption) (*pb.ListUserDevicesResp, error) {
	return &pb.ListUserDevicesResp{Devices: m.listResult}, nil
}
func (m *deviceMock) CreateDevice(ctx context.Context, in *pb.CreateDeviceReq, _ ...grpc.CallOption) (*pb.CreateDeviceResp, error) {
	m.created = append(m.created, in)
	return &pb.CreateDeviceResp{Device: &pb.Device{Id: "dev-new", UserId: in.GetUserId(), Identifier: in.GetIdentifier(), Label: in.GetLabel(), Ip: in.GetIp()}}, nil
}
func (m *deviceMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	m.issuedWith = append(m.issuedWith, in)
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "tok-1", UserId: in.GetUserId(), DeviceId: in.GetDeviceId()}}, nil
}
func (m *deviceMock) TrustDevice(ctx context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	m.trusted = append(m.trusted, in)
	return &pb.TrustDeviceResp{DeviceId: in.GetDeviceId()}, nil
}
func (m *deviceMock) DeleteDeviceTokens(ctx context.Context, in *pb.DeleteDeviceTokensReq, _ ...grpc.CallOption) (*pb.DeleteDeviceTokensResp, error) {
	m.deletedTokens = append(m.deletedTokens, in)
	return &pb.DeleteDeviceTokensResp{DeviceId: in.GetDeviceId()}, nil
}
func (m *deviceMock) DeleteDevice(ctx context.Context, in *pb.DeleteDeviceReq, _ ...grpc.CallOption) (*pb.DeleteDeviceResp, error) {
	m.deletedDevs = append(m.deletedDevs, in)
	return &pb.DeleteDeviceResp{DeviceId: in.GetDeviceId()}, nil
}
func (m *deviceMock) DeleteAllUserTokens(ctx context.Context, in *pb.DeleteAllUserTokensReq, _ ...grpc.CallOption) (*pb.DeleteAllUserTokensResp, error) {
	m.allTokensFor = in.GetUserId()
	return &pb.DeleteAllUserTokensResp{UserId: in.GetUserId()}, nil
}
func (m *deviceMock) DeleteAllUserDevices(ctx context.Context, in *pb.DeleteAllUserDevicesReq, _ ...grpc.CallOption) (*pb.DeleteAllUserDevicesResp, error) {
	m.allDevsFor = in.GetUserId()
	return &pb.DeleteAllUserDevicesResp{UserId: in.GetUserId()}, nil
}

// ctxWithDeviceTrust builds a request context carrying X-Device-Id +
// X-Device-Trust, so a test can exercise the trust-token replay path.
func ctxWithDeviceTrust(uid, deviceID, trustToken string) context.Context {
	pairs := []string{scopeUserIDKey, uid}
	if deviceID != "" {
		pairs = append(pairs, deviceIDMetadataKey, deviceID)
	}
	if trustToken != "" {
		pairs = append(pairs, deviceTrustMetadataKey, trustToken)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func ctxWithDeviceHeaders(uid, deviceID, ua, ip string) context.Context {
	pairs := []string{scopeUserIDKey, uid}
	if deviceID != "" {
		pairs = append(pairs, deviceIDMetadataKey, deviceID)
	}
	if ua != "" {
		pairs = append(pairs, userAgentMetadataKey, ua)
	}
	if ip != "" {
		pairs = append(pairs, clientIPMetadataKey, ip)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestResolveDeviceIdentity_HeaderWins(t *testing.T) {
	ctx := ctxWithDeviceHeaders("u1", "phone-123", "Mozilla/5.0", "203.0.113.7, 10.0.0.1")
	di := resolveDeviceIdentity(ctx)
	if di.identifier != "phone-123" {
		t.Errorf("identifier = %q, want header value phone-123", di.identifier)
	}
	if di.label != "Mozilla/5.0" {
		t.Errorf("label = %q, want the user-agent", di.label)
	}
	if di.ip != "203.0.113.7" {
		t.Errorf("ip = %q, want first X-Forwarded-For hop", di.ip)
	}
}

func TestResolveDeviceIdentity_FingerprintFallback(t *testing.T) {
	a := resolveDeviceIdentity(ctxWithDeviceHeaders("u1", "", "UA-X", "1.2.3.4"))
	b := resolveDeviceIdentity(ctxWithDeviceHeaders("u1", "", "UA-X", "1.2.3.4"))
	c := resolveDeviceIdentity(ctxWithDeviceHeaders("u1", "", "UA-Y", "1.2.3.4"))
	if a.identifier == "" || len(a.identifier) != 64 {
		t.Fatalf("fingerprint should be a 64-hex sha256, got %q", a.identifier)
	}
	if a.identifier != b.identifier {
		t.Error("same UA+IP must yield a stable fingerprint")
	}
	if a.identifier == c.identifier {
		t.Error("different UA must yield a different fingerprint")
	}
}

func TestResolveSignInDevice_NewDevice_Creates_Untrusted(t *testing.T) {
	m := &deviceMock{getByIdent: map[string]*pb.Device{}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	id, trusted, err := resolveSignInDeviceImpl(ctxWithDeviceHeaders("u1", "phone-1", "UA", "9.9.9.9"), h, "u1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "dev-new" {
		t.Errorf("device id = %q, want dev-new (created)", id)
	}
	if trusted {
		t.Error("a freshly-created device must be untrusted")
	}
	if len(m.created) != 1 || m.created[0].GetIdentifier() != "phone-1" {
		t.Errorf("expected one CreateDevice for phone-1, got %+v", m.created)
	}
}

// A device with a stored trust hash is trusted only when the request
// replays the matching token (proving possession of the server-issued
// secret). The X-Device-Id alone no longer trusts.
func TestResolveSignInDevice_ValidTrustToken_Trusted(t *testing.T) {
	const tok = "trust-tok-abc"
	m := &deviceMock{getByIdent: map[string]*pb.Device{
		devKey("u1", "phone-1"): {Id: "dev-7", Identifier: "phone-1", TrustedAt: timestamppb.Now(), TrustTokenHash: hashDeviceTrustToken(tok)},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	id, trusted, err := resolveSignInDeviceImpl(ctxWithDeviceTrust("u1", "phone-1", tok), h, "u1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "dev-7" || !trusted {
		t.Errorf("device replaying a valid trust token: got id=%q trusted=%v, want dev-7/true", id, trusted)
	}
	if len(m.created) != 0 {
		t.Error("known device must not be re-created")
	}
}

// A device flagged trusted_at but presenting NO trust token (e.g. a row stored
// before the device-trust token existed, or an attacker who only learnt the
// victim's X-Device-Id) is NOT trusted: it re-challenges.
func TestResolveSignInDevice_TrustedAtButNoToken_NotTrusted(t *testing.T) {
	m := &deviceMock{getByIdent: map[string]*pb.Device{
		devKey("u1", "phone-1"): {Id: "dev-7", Identifier: "phone-1", TrustedAt: timestamppb.Now()}, // no TrustTokenHash
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, trusted, err := resolveSignInDeviceImpl(ctxWithDeviceHeaders("u1", "phone-1", "UA", "9.9.9.9"), h, "u1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if trusted {
		t.Error("a trusted_at device with no stored trust hash / no presented token must NOT be trusted (X-Device-Id is not a trust factor)")
	}
}

// A wrong trust token does not trust the device.
func TestResolveSignInDevice_WrongTrustToken_NotTrusted(t *testing.T) {
	m := &deviceMock{getByIdent: map[string]*pb.Device{
		devKey("u1", "phone-1"): {Id: "dev-7", Identifier: "phone-1", TrustedAt: timestamppb.Now(), TrustTokenHash: hashDeviceTrustToken("the-real-token")},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, trusted, err := resolveSignInDeviceImpl(ctxWithDeviceTrust("u1", "phone-1", "a-wrong-token"), h, "u1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if trusted {
		t.Error("a wrong trust token must NOT trust the device")
	}
}

// issueSessionWithDevice mints a fresh trust token, stores its hash,
// and returns the plaintext for the client to replay.
func TestIssueSessionWithDevice_IssuesMintsAndTrusts(t *testing.T) {
	m := &deviceMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	tok, trustToken, err := issueSessionWithDevice(context.Background(), h, "u1", "dev-7", true)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" || len(m.issuedWith) != 1 || m.issuedWith[0].GetTokenHash() != sha256Hex(tok) {
		t.Errorf("token = %q: the store must get sha256 of the token handed out", tok)
	}
	if trustToken == "" {
		t.Fatal("issueSessionWithDevice must return a non-empty device-trust token")
	}
	if len(m.issuedWith) != 1 || m.issuedWith[0].GetDeviceId() != "dev-7" {
		t.Errorf("expected IssueToken stamped with device dev-7, got %+v", m.issuedWith)
	}
	if len(m.trusted) != 1 || m.trusted[0].GetDeviceId() != "dev-7" {
		t.Fatalf("expected TrustDevice(dev-7), got %+v", m.trusted)
	}
	// The stored hash must be the hash of the returned plaintext (never the
	// plaintext itself).
	if got := m.trusted[0].GetTrustTokenHash(); got != hashDeviceTrustToken(trustToken) {
		t.Errorf("stored trust hash %q != hash(returned token); plaintext must not be stored", got)
	}
	if m.trusted[0].GetTrustTokenHash() == trustToken {
		t.Error("the plaintext trust token must never be stored")
	}
}

func TestSignIn_DevicesSeams_WiredViaInit(t *testing.T) {
	// init() in devices.go must have swapped both sign-in seams.
	m := &deviceMock{getByIdent: map[string]*pb.Device{}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	id, trusted, err := resolveSignInDevice(ctxWithDeviceHeaders("u1", "d1", "UA", "1.1.1.1"), h, "u1")
	if err != nil || id == "" {
		t.Fatalf("resolveSignInDevice seam not wired: id=%q err=%v", id, err)
	}
	_ = trusted
	if _, _, err := issueSession(context.Background(), h, "u1", "d1", true); err != nil {
		t.Fatalf("issueSession seam not wired: %v", err)
	}
	if len(m.issuedWith) == 0 {
		t.Error("issueSession seam should issue a token carrying device_id")
	}
}

func TestListDevices_MarksTrustedAndCurrent(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{
		{Id: "dev-cur", Identifier: "phone-1", Label: "Phone", TrustedAt: timestamppb.Now()},
		{Id: "dev-other", Identifier: "laptop-9", Label: "Laptop"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListDevices(ctxWithDeviceHeaders("u1", "phone-1", "UA", "1.1.1.1"), &pb.ListDevicesReq{})
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
}

func TestListDevices_NoCaller_Unauthenticated(t *testing.T) {
	h := &AuthServiceHandler{Query: &deviceMock{}, Mutation: &deviceMock{}}
	if _, err := h.ListDevices(context.Background(), &pb.ListDevicesReq{}); err == nil {
		t.Fatal("expected Unauthenticated without caller scope")
	}
}

func TestRevokeDevice_DeletesTokensThenDevice(t *testing.T) {
	m := &deviceMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeDevice(ctxWithDeviceHeaders("u1", "", "", ""), &pb.RevokeDeviceReq{DeviceId: "dev-7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(m.deletedTokens) != 1 || m.deletedTokens[0].GetUserId() != "u1" || m.deletedTokens[0].GetDeviceId() != "dev-7" {
		t.Errorf("token delete guard wrong: %+v", m.deletedTokens)
	}
	if len(m.deletedDevs) != 1 || m.deletedDevs[0].GetDeviceId() != "dev-7" {
		t.Errorf("device delete wrong: %+v", m.deletedDevs)
	}
}

func TestRevokeOtherDevices_KeepsCurrent(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{
		{Id: "dev-cur", Identifier: "phone-1"},
		{Id: "dev-a", Identifier: "laptop-a"},
		{Id: "dev-b", Identifier: "tablet-b"},
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeOtherDevices(ctxWithDeviceHeaders("u1", "phone-1", "UA", "1.1.1.1"), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatalf("revoke-others: %v", err)
	}
	if len(m.deletedDevs) != 2 {
		t.Fatalf("want 2 devices revoked (not the current), got %d", len(m.deletedDevs))
	}
	for _, d := range m.deletedDevs {
		if d.GetDeviceId() == "dev-cur" {
			t.Error("must not revoke the current device")
		}
	}
}

// RevokeAllDevices must revoke each device's tokens individually
// (DeleteDeviceTokens is device_id-filtered) + the device row — NOT the broad
// DeleteAllUserTokens, which has no token_type filter and would also delete the
// user's API tokens (device_id NULL), credentials that should only be removed
// via RevokeApiToken.
func TestRevokeAllDevices_PerDeviceSparesApiTokens(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{{Id: "dev-1"}, {Id: "dev-2"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeAllDevices(ctxWithDeviceHeaders("u1", "", "", ""), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if m.allTokensFor != "" {
		t.Errorf("revoke-all must NOT call DeleteAllUserTokens (it deletes API tokens too); got %q", m.allTokensFor)
	}
	if len(m.deletedTokens) != 2 || len(m.deletedDevs) != 2 {
		t.Errorf("revoke-all must delete tokens+device per device (2 each); got %d token-deletes, %d device-deletes",
			len(m.deletedTokens), len(m.deletedDevs))
	}
}

// notFoundMock returns NotFound from the device-delete mutations, so the
// revoke RPCs must swallow it (idempotent: revoking an already-gone device
// is a no-op, not an error).
type notFoundMock struct{ deviceMock }

func (notFoundMock) DeleteDeviceTokens(ctx context.Context, in *pb.DeleteDeviceTokensReq, _ ...grpc.CallOption) (*pb.DeleteDeviceTokensResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) DeleteDevice(ctx context.Context, in *pb.DeleteDeviceReq, _ ...grpc.CallOption) (*pb.DeleteDeviceResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) DeleteUndevicedSessions(ctx context.Context, in *pb.DeleteUndevicedSessionsReq, _ ...grpc.CallOption) (*pb.DeleteUndevicedSessionsResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) DeleteAllUserTokens(ctx context.Context, in *pb.DeleteAllUserTokensReq, _ ...grpc.CallOption) (*pb.DeleteAllUserTokensResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}
func (notFoundMock) DeleteAllUserDevices(ctx context.Context, in *pb.DeleteAllUserDevicesReq, _ ...grpc.CallOption) (*pb.DeleteAllUserDevicesResp, error) {
	return nil, status.Error(codes.NotFound, "not found")
}

func TestRevokeDevice_IdempotentOnMissing(t *testing.T) {
	m := &notFoundMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeDevice(ctxWithCaller("u1"), &pb.RevokeDeviceReq{DeviceId: "ghost"}); err != nil {
		t.Errorf("revoking a missing device must be a no-op, got %v", err)
	}
	if _, err := h.RevokeAllDevices(ctxWithCaller("u1"), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Errorf("revoke-all on a token-less user must be a no-op, got %v", err)
	}
}

// Not every session is device-bound — SignUp, ConfirmSignUp, the OAuth
// callback and CliToken issue one with no device — so "log out everywhere"
// must sweep those too, keeping none; "log out the others" keeps only the
// caller's own: a registration's session must not survive RevokeAllDevices.
func TestRevokeDevices_SweepSessionsNoDeviceHolds(t *testing.T) {
	m := &deviceMock{listResult: []*pb.Device{{Id: "dev-a", Identifier: "laptop-a"}}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.RevokeAllDevices(ctxWithDeviceHeaders("u1", "laptop-a", "UA", "1.1.1.1"), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	if len(m.undeviced) != 1 || m.undeviced[0].GetUserId() != "u1" || m.undeviced[0].GetKeepTokenId() != noTokenKept {
		t.Fatalf("revoke-all: device-less sessions not swept, keeping none: %+v", m.undeviced)
	}
	m.undeviced = nil
	if _, err := h.RevokeOtherDevices(ctxWithDeviceHeaders("u1", "laptop-a", "UA", "1.1.1.1"), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	if len(m.undeviced) != 1 || m.undeviced[0].GetUserId() != "u1" {
		t.Fatalf("revoke-others: device-less sessions not swept: %+v", m.undeviced)
	}
	// Nothing to sweep is the ordinary case, not a failure.
	nf := &notFoundMock{}
	hn := &AuthServiceHandler{Query: nf, Mutation: nf}
	if _, err := hn.RevokeAllDevices(ctxWithDeviceHeaders("u1", "x", "UA", "1.1.1.1"), &pb.RevokeAllDevicesReq{}); err != nil {
		t.Fatalf("an empty sweep must not fail revoke-all: %v", err)
	}
}

// The browser's User-Agent arrives as x-forwarded-user-agent (the gRPC hop
// overwrites user-agent with its own); it labels the device and feeds the
// fingerprint. user-agent stays the fallback.
func TestResolveDeviceIdentity_PrefersTheForwardedUserAgent(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"user-agent", "grpc-go/1.83.2", "x-forwarded-user-agent", "Firefox/140", "x-forwarded-for", "10.0.0.1"))
	di := resolveDeviceIdentity(ctx)
	if di.label != "Firefox/140" {
		t.Fatalf("label = %q, want the browser's UA", di.label)
	}
	other := resolveDeviceIdentity(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"user-agent", "grpc-go/1.83.2", "x-forwarded-user-agent", "Safari/18", "x-forwarded-for", "10.0.0.1")))
	if other.identifier == di.identifier {
		t.Fatal("two browsers on one address fingerprint as one device")
	}
	fallback := resolveDeviceIdentity(metadata.NewIncomingContext(context.Background(), metadata.Pairs("user-agent", "curl/8")))
	if fallback.label != "curl/8" {
		t.Fatalf("fallback label = %q", fallback.label)
	}
}

// A sign-in that may not earn trust (OAuth, which skipped the second factor)
// binds its session to the device but neither trusts it nor hands out a
// trust token: under two_factor_scope=new_devices a trusted device skips the
// second factor for password sign-ins too.
func TestIssueSessionWithDevice_BindsWithoutTrustingWhenNotAllowed(t *testing.T) {
	m := &deviceMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	tok, trustToken, err := issueSessionWithDevice(context.Background(), h, "u1", "dev-7", false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" || len(m.issuedWith) != 1 || m.issuedWith[0].GetDeviceId() != "dev-7" {
		t.Errorf("the session was not bound to the device: %+v", m.issuedWith)
	}
	if trustToken != "" || len(m.trusted) != 0 {
		t.Errorf("an untrusting sign-in trusted the device (trust token %q, TrustDevice %+v)", trustToken, m.trusted)
	}
}

// signInDeviceMock adds the account lookup SignIn needs to deviceMock.
type signInDeviceMock struct {
	*deviceMock
	user *pb.User
}

func (m signInDeviceMock) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: m.user}, nil
}

// A password sign-in that met no second factor renews the trust of a device
// that already has it, and grants none to a device that does not. Granted on
// the password alone, every device that ever signed in would skip the factor
// once two_factor_scope=new_devices is switched on.
func TestSignIn_RenewsDeviceTrustButNeverGrantsIt(t *testing.T) {
	saved := signInMfaGate
	signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool) (*pb.SignInResp, bool, error) {
		return nil, false, nil // two_factor off: no factor asked for
	}
	t.Cleanup(func() { signInMfaGate = saved })

	hashed, err := testPasswordSettings().Hash("pw-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	trustPlain, trustHash, err := newDeviceTrustToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		device  *pb.Device
		ctx     context.Context
		trusted bool
	}{
		{"untrusted device", &pb.Device{Id: "dev-1", Identifier: "d1"}, ctxWithDeviceTrust("", "d1", ""), false},
		{"trusted device", &pb.Device{Id: "dev-1", Identifier: "d1", TrustedAt: timestamppb.Now(), TrustTokenHash: trustHash}, ctxWithDeviceTrust("", "d1", trustPlain), true},
	} {
		dm := &deviceMock{getByIdent: map[string]*pb.Device{devKey("u1", "d1"): c.device}}
		m := signInDeviceMock{deviceMock: dm, user: &pb.User{Id: "u1", Email: "a@b.c", PasswordHash: hashed}}
		h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
		resp, err := h.SignIn(c.ctx, &pb.SignInReq{Email: "a@b.c", Password: "pw-long-enough"})
		if err != nil {
			t.Fatalf("%s: sign-in: %v", c.name, err)
		}
		if got := len(dm.trusted) == 1 && resp.GetDeviceTrustToken() != ""; got != c.trusted {
			t.Errorf("%s: trusted = %v (TrustDevice %+v), want %v", c.name, got, dm.trusted, c.trusted)
		}
	}
}

// Trust granted before the account's last revocation (a password change or a
// disable stamps User.device_trust_revoked_at) does not count, even with the
// right trust token replayed: the device passes the second factor again.
func TestResolveSignInDevice_TrustRevokedByACredentialChange_NotTrusted(t *testing.T) {
	const tok = "trust-tok-abc"
	trustedAt := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	before := timestamppb.New(trustedAt.AsTime().Add(-time.Hour))
	after := timestamppb.New(trustedAt.AsTime().Add(time.Hour))
	for _, c := range []struct {
		name      string
		revokedAt *timestamppb.Timestamp
		readErr   error
		trusted   bool
	}{
		{"never revoked", nil, nil, true},
		{"revoked before the trust was granted", before, nil, true},
		{"revoked after the trust was granted", after, nil, false},
		{"revoked at the same instant", trustedAt, nil, false},
		{"the revocation cannot be read", nil, status.Error(codes.Unavailable, "db down"), false},
	} {
		m := &deviceMock{
			getByIdent: map[string]*pb.Device{
				devKey("u1", "phone-1"): {Id: "dev-7", Identifier: "phone-1", TrustedAt: trustedAt, TrustTokenHash: hashDeviceTrustToken(tok)},
			},
			revokedAt:  c.revokedAt,
			revokedErr: c.readErr,
		}
		h := &AuthServiceHandler{Query: m, Mutation: m}
		id, trusted, err := resolveSignInDeviceImpl(ctxWithDeviceTrust("u1", "phone-1", tok), h, "u1")
		if err != nil {
			t.Fatalf("%s: resolve: %v", c.name, err)
		}
		if id != "dev-7" || trusted != c.trusted {
			t.Errorf("%s: got id=%q trusted=%v, want dev-7/%v", c.name, id, trusted, c.trusted)
		}
	}
}

// A password sign-in renews only trust that still stands: after a password
// change or a disable, the device's earlier trust is not renewed by the
// password alone (it would be laundered back to "trusted" otherwise).
func TestSignIn_DoesNotRenewRevokedDeviceTrust(t *testing.T) {
	saved := signInMfaGate
	signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool) (*pb.SignInResp, bool, error) {
		return nil, false, nil // two_factor off: no factor asked for
	}
	t.Cleanup(func() { signInMfaGate = saved })

	hashed, err := testPasswordSettings().Hash("pw-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	trustPlain, trustHash, err := newDeviceTrustToken()
	if err != nil {
		t.Fatal(err)
	}
	trustedAt := timestamppb.New(time.Now().Add(-time.Hour))
	dm := &deviceMock{
		getByIdent: map[string]*pb.Device{devKey("u1", "d1"): {Id: "dev-1", Identifier: "d1", TrustedAt: trustedAt, TrustTokenHash: trustHash}},
		revokedAt:  timestamppb.Now(),
	}
	m := signInDeviceMock{deviceMock: dm, user: &pb.User{Id: "u1", Email: "a@b.c", PasswordHash: hashed}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	resp, err := h.SignIn(ctxWithDeviceTrust("", "d1", trustPlain), &pb.SignInReq{Email: "a@b.c", Password: "pw-long-enough"})
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if resp.GetToken() == "" {
		t.Error("the sign-in itself must still succeed")
	}
	if len(dm.trusted) != 0 || resp.GetDeviceTrustToken() != "" {
		t.Errorf("revoked trust was renewed (TrustDevice %+v, trust token %q)", dm.trusted, resp.GetDeviceTrustToken())
	}
}

// ListDevices applies the sign-in's rule: a device trusted before the
// account's last revocation is listed as untrusted, so the list never claims a
// device skips the second factor when it does not. A revocation that cannot be
// read fails the list rather than guessing.
func TestListDevices_TrustRevokedByACredentialChange_NotShownTrusted(t *testing.T) {
	old := timestamppb.New(time.Now().Add(-2 * time.Hour))
	fresh := timestamppb.Now()
	m := &deviceMock{
		listResult: []*pb.Device{
			{Id: "dev-old", Identifier: "phone-1", TrustedAt: old},
			{Id: "dev-new", Identifier: "laptop-9", TrustedAt: fresh},
		},
		revokedAt: timestamppb.New(time.Now().Add(-time.Hour)),
	}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.ListDevices(ctxWithDeviceHeaders("u1", "phone-1", "UA", "1.1.1.1"), &pb.ListDevicesReq{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := resp.GetDevices(); len(got) != 2 || got[0].GetTrusted() || !got[1].GetTrusted() {
		t.Errorf("want dev-old untrusted (trusted before the revocation) and dev-new trusted, got %+v", got)
	}

	m.revokedErr = status.Error(codes.Unavailable, "db down")
	if _, err := h.ListDevices(ctxWithDeviceHeaders("u1", "phone-1", "UA", "1.1.1.1"), &pb.ListDevicesReq{}); status.Code(err) != codes.Unavailable {
		t.Errorf("an unreadable revocation must fail the list, got %v", err)
	}
}
