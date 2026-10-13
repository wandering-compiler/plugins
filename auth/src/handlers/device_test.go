package handlers

import (
	"context"
	"errors"
	"os"
	"strings"
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

// Two device keys, as RFC 7638 thumbprints (43 base64url characters).
const (
	testJKT  = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	otherJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

// withJKT adds the gateway's possession thumbprint to ctx's incoming
// metadata, as the gateway stamps it on a mint request.
func withJKT(ctx context.Context, jkt string) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(dpopJKTKey, jkt)
	return metadata.NewIncomingContext(ctx, md)
}

// mintCtx is a mint request from the device testJKT.
func mintCtx() context.Context { return withJKT(context.Background(), testJKT) }

// fakeRegisterDevice answers RegisterDevice for a mock that only needs a live,
// untrusted device to bind a token to: a fresh row named after the key.
func fakeRegisterDevice(in *pb.RegisterDeviceReq) (*pb.RegisterDeviceResp, error) {
	return &pb.RegisterDeviceResp{Device: &pb.Device{
		Id:         "dev-" + in.GetThumbprint()[:8],
		UserId:     in.GetUserId(),
		Thumbprint: in.GetThumbprint(),
	}}, nil
}

// boundAuthReq is a request carrying token under the DPoP scheme with a proof
// by jkt, as the gateway hands it to Authenticate.
func boundAuthReq(token, jkt string) *pb.AuthReq {
	return &pb.AuthReq{Headers: map[string]string{"authorization": "DPoP " + token, dpopJKTKey: jkt}}
}

// deviceStore is the Device table as the statements keep it — one row per
// (user_id, thumbprint), found or created by RegisterDevice's UPSERT — plus
// the account's trust revocation and the token and trust writes a mint makes.
type deviceStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	rows map[string]*pb.Device // user|thumbprint
	seq  int

	registered []*pb.RegisterDeviceReq
	issued     []*pb.IssueTokenReq
	trusted    []*pb.TrustDeviceReq

	// User.device_trust_revoked_at, and a read failure for it
	revokedAt  *timestamppb.Timestamp
	revokedErr error
	revokeRead int
	// a revocation that commits AFTER the sign-in read revokedAt: the value
	// TrustDevice's guard sees (nil = none)
	revokedLater *timestamppb.Timestamp
	trustErr     error
}

func newDeviceStore() *deviceStore { return &deviceStore{rows: map[string]*pb.Device{}} }

func devKey(user, jkt string) string { return user + "|" + jkt }

// put seeds a row for (user, jkt) and returns it.
func (s *deviceStore) put(user, jkt string, d *pb.Device) *pb.Device {
	d.UserId, d.Thumbprint = user, jkt
	if d.Id == "" {
		s.seq++
		d.Id = "dev-" + string(rune('0'+s.seq))
	}
	s.rows[devKey(user, jkt)] = d
	return d
}

func (s *deviceStore) RegisterDevice(_ context.Context, in *pb.RegisterDeviceReq, _ ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	s.registered = append(s.registered, in)
	d, ok := s.rows[devKey(in.GetUserId(), in.GetThumbprint())]
	if !ok {
		d = s.put(in.GetUserId(), in.GetThumbprint(), &pb.Device{})
	}
	d.Label, d.Ip, d.LastSeenAt = in.GetLabel(), in.GetIp(), timestamppb.Now()
	return &pb.RegisterDeviceResp{Device: proto.Clone(d).(*pb.Device)}, nil
}

func (s *deviceStore) IssueToken(_ context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	s.issued = append(s.issued, in)
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "tok-1", UserId: in.GetUserId(), DeviceId: in.GetDeviceId()}}, nil
}

func (s *deviceStore) GetDeviceTrustRevokedAt(context.Context, *pb.GetDeviceTrustRevokedAtReq, ...grpc.CallOption) (*pb.GetDeviceTrustRevokedAtResp, error) {
	s.revokeRead++
	if s.revokedErr != nil {
		return nil, s.revokedErr
	}
	return &pb.GetDeviceTrustRevokedAtResp{DeviceTrustRevokedAt: s.revokedAt}, nil
}

// TrustDevice mirrors its statement's guards: a revoked device, or a
// revocation later than the cutoff, matches no row (NotFound, nothing
// written).
func (s *deviceStore) TrustDevice(_ context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	if s.trustErr != nil {
		return nil, s.trustErr
	}
	current := s.revokedAt
	if s.revokedLater != nil {
		current = s.revokedLater
	}
	if cut := in.GetNotRevokedAfter(); current != nil && cut != nil && current.AsTime().After(cut.AsTime()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	for _, d := range s.rows {
		if d.GetId() == in.GetDeviceId() && d.GetUserId() == in.GetUserId() {
			if d.GetRevokedAt() != nil {
				return nil, status.Error(codes.NotFound, "no rows")
			}
			d.TrustedAt = timestamppb.Now()
		}
	}
	s.trusted = append(s.trusted, in)
	return &pb.TrustDeviceResp{DeviceId: in.GetDeviceId()}, nil
}

// signInStore adds the account lookup SignIn needs to the device store.
type signInStore struct {
	*deviceStore
	users  map[string]*pb.User // by email
	lookup int
}

func (m *signInStore) GetUserByEmail(_ context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	m.lookup++
	u, ok := m.users[in.GetEmail()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserByEmailResp{User: u}, nil
}

const devicePassword = "pw-long-enough"

func newSignInStore(t *testing.T, users ...string) (*signInStore, *AuthServiceHandler) {
	t.Helper()
	hashed, err := testPasswordSettings().Hash(devicePassword)
	if err != nil {
		t.Fatal(err)
	}
	m := &signInStore{deviceStore: newDeviceStore(), users: map[string]*pb.User{}}
	for _, u := range users {
		m.users[u+"@example.com"] = &pb.User{Id: u, Email: u + "@example.com", PasswordHash: hashed}
	}
	return m, &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
}

// noSecondFactor swaps in the two_factor gate the way an activation without
// it behaves, recording the trust signal each sign-in handed it.
func noSecondFactor(t *testing.T) *[]bool {
	t.Helper()
	saved := signInMfaGate
	var seen []bool
	signInMfaGate = func(_ context.Context, _ *AuthServiceHandler, _ *pb.User, _ string, trusted bool) (*pb.SignInResp, bool, error) {
		seen = append(seen, trusted)
		return nil, false, nil
	}
	t.Cleanup(func() { signInMfaGate = saved })
	return &seen
}

// wantDeviceRefusal asserts err is the device refusal `code`: Unauthenticated,
// with the ErrorDetail and the google.rpc.ErrorInfo (domain auth.w17) both
// carrying it.
func wantDeviceRefusal(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no refusal, want %s", code)
	}
	st, ed, info := expiryDetails(t, err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("code = %v (%v), want Unauthenticated/%s", st.Code(), err, code)
	}
	if ed.GetCode() != code || ed.GetMessage() == "" {
		t.Fatalf("ErrorDetail = %v, want code %s with a sentence", ed, code)
	}
	if info.GetReason() != code || info.GetDomain() != ErrorDomain {
		t.Fatalf("ErrorInfo = %+v, want reason %s domain %s", info, code, ErrorDomain)
	}
}

// ── the proof on a mint request ─────────────────────────────

// device/no-unbound-credential: no thumbprint, or anything that is not one,
// is no proof — refused before a token could exist.
func TestMintThumbprint_RefusesAMissingOrMalformedProof(t *testing.T) {
	for _, c := range []struct {
		name string
		ctx  context.Context
	}{
		{"no metadata", context.Background()},
		{"empty", withJKT(context.Background(), "")},
		{"42 characters", withJKT(context.Background(), testJKT[:42])},
		{"44 characters", withJKT(context.Background(), testJKT+"A")},
		{"padding", withJKT(context.Background(), testJKT[:42]+"=")},
		{"standard base64", withJKT(context.Background(), testJKT[:42]+"+")},
	} {
		_, err := mintThumbprint(c.ctx)
		wantDeviceRefusal(t, err, CodeDeviceProofRequired)
	}
	got, err := mintThumbprint(mintCtx())
	if err != nil || got != testJKT {
		t.Fatalf("a valid thumbprint = %q, %v", got, err)
	}
}

// ── registering the device ──────────────────────────────────

func TestMintDevice_ANewDeviceIsRegisteredUntrusted(t *testing.T) {
	m := newDeviceStore()
	h := &AuthServiceHandler{Query: m, Mutation: m}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"user-agent", "grpc-go/1.83.2", "x-forwarded-user-agent", "Firefox/140", "x-forwarded-for", "203.0.113.7, 10.0.0.1"))
	dev, err := mintDevice(ctx, h, "u1", testJKT)
	if err != nil {
		t.Fatal(err)
	}
	if dev.id == "" || dev.trusted || dev.trustCutoff != nil {
		t.Fatalf("new device = %+v, want an id and no trust", dev)
	}
	r := m.registered
	if len(r) != 1 || r[0].GetUserId() != "u1" || r[0].GetThumbprint() != testJKT ||
		r[0].GetLabel() != "Firefox/140" || r[0].GetIp() != "203.0.113.7" {
		t.Fatalf("RegisterDevice = %+v, want (u1, the key) labelled with the browser's UA and the first hop", r)
	}
	if m.revokeRead != 0 {
		t.Error("a device with no trust needs no revocation read")
	}
}

// device/revoked-refused-for-good: a revoked (user, device) is refused at
// every mint, and stays revoked — nothing in the mint revives it.
func TestMintDevice_ARevokedDeviceIsRefusedForGood(t *testing.T) {
	m := newDeviceStore()
	m.put("u1", testJKT, &pb.Device{RevokedAt: timestamppb.Now(), TrustedAt: timestamppb.Now()})
	h := &AuthServiceHandler{Query: m, Mutation: m}
	for i := 0; i < 2; i++ {
		_, err := mintDevice(mintCtx(), h, "u1", testJKT)
		wantDeviceRefusal(t, err, CodeDeviceRevoked)
	}
	if m.rows[devKey("u1", testJKT)].GetRevokedAt() == nil {
		t.Fatal("the refusal revived the device")
	}
	// Another key of the same account is a new device and is not refused.
	if _, err := mintDevice(mintCtx(), h, "u1", otherJKT); err != nil {
		t.Fatalf("a new key after a revocation: %v", err)
	}
}

func TestMintDevice_AStoreThatAnswersNoRowBindsNothing(t *testing.T) {
	m := &emptyRegisterStore{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := mintDevice(mintCtx(), h, "u1", testJKT); !errors.Is(err, errDeviceNotRegistered) {
		t.Fatalf("err = %v, want errDeviceNotRegistered", err)
	}
	if _, err := h.issueBoundToken(mintCtx(), "u1", "", h.sessionTokenExpiry()); !errors.Is(err, errDeviceNotRegistered) {
		t.Fatalf("an unbound mint: err = %v, want errDeviceNotRegistered", err)
	}
}

type emptyRegisterStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
}

func (emptyRegisterStore) RegisterDevice(context.Context, *pb.RegisterDeviceReq, ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	return &pb.RegisterDeviceResp{}, nil
}

// Trust granted before the account's last revocation (a password change or a
// disable stamps User.device_trust_revoked_at) does not count.
func TestMintDevice_TrustRevokedByACredentialChange_NotTrusted(t *testing.T) {
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
		m := newDeviceStore()
		m.put("u1", testJKT, &pb.Device{Id: "dev-7", TrustedAt: trustedAt})
		m.revokedAt, m.revokedErr = c.revokedAt, c.readErr
		h := &AuthServiceHandler{Query: m, Mutation: m}
		dev, err := mintDevice(mintCtx(), h, "u1", testJKT)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if dev.id != "dev-7" || dev.trusted != c.trusted {
			t.Errorf("%s: got %+v, want dev-7 trusted=%v", c.name, dev, c.trusted)
		}
	}
}

// ── issuing the token ───────────────────────────────────────

// device/no-unbound-credential: the session is bound to the device; trust is
// written only with a cutoff, and only for that device.
func TestIssueSession_BindsAndTrustsOnlyWithACutoff(t *testing.T) {
	for _, c := range []struct {
		name   string
		cutoff *timestamppb.Timestamp
		trust  bool
	}{
		{"may not trust (OAuth, a new device)", nil, false},
		{"may trust (second factor passed)", neverRevoked, true},
	} {
		m := newDeviceStore()
		h := &AuthServiceHandler{Query: m, Mutation: m}
		tok, err := issueSession(context.Background(), h, "u1", "dev-7", c.cutoff)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(m.issued) != 1 || m.issued[0].GetDeviceId() != "dev-7" || m.issued[0].GetTokenHash() != sha256Hex(tok) {
			t.Fatalf("%s: IssueToken = %+v, want bound to dev-7 storing sha256 of the token", c.name, m.issued)
		}
		if got := len(m.trusted) == 1 && m.trusted[0].GetDeviceId() == "dev-7"; got != c.trust {
			t.Errorf("%s: trusted = %v (%+v), want %v", c.name, got, m.trusted, c.trust)
		}
	}
}

// ── SignIn ──────────────────────────────────────────────────

// device/no-unbound-credential: a sign-in without a proof is refused before
// the account is looked up — nothing is learned about the address, and no
// token can be minted unbound.
func TestSignIn_WithoutAProofIsRefusedBeforeTheLookup(t *testing.T) {
	m, h := newSignInStore(t, "u1")
	_, err := h.SignIn(context.Background(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	wantDeviceRefusal(t, err, CodeDeviceProofRequired)
	if m.lookup != 0 || len(m.registered) != 0 || len(m.issued) != 0 {
		t.Fatalf("a refused sign-in reached storage: %d lookups, %+v registered, %+v issued", m.lookup, m.registered, m.issued)
	}
}

func TestSignIn_BindsTheSessionToTheProofsDevice(t *testing.T) {
	noSecondFactor(t)
	m, h := newSignInStore(t, "u1")
	resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if err != nil {
		t.Fatal(err)
	}
	dev := m.rows[devKey("u1", testJKT)]
	if dev == nil || len(m.issued) != 1 || m.issued[0].GetDeviceId() != dev.GetId() || m.issued[0].GetTokenHash() != sha256Hex(resp.GetToken()) {
		t.Fatalf("session not bound to (u1, the key): device %+v, IssueToken %+v", dev, m.issued)
	}
}

// device/revoked-refused-for-good at sign-in: after the password (only someone
// who knows it learns the device's state), and with no token.
func TestSignIn_ARevokedDeviceIsRefused(t *testing.T) {
	noSecondFactor(t)
	m, h := newSignInStore(t, "u1")
	m.put("u1", testJKT, &pb.Device{RevokedAt: timestamppb.Now()})

	_, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	wantDeviceRefusal(t, err, CodeDeviceRevoked)
	if len(m.issued) != 0 {
		t.Fatalf("a revoked device got a token: %+v", m.issued)
	}

	// A wrong password says nothing about the device.
	_, err = h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: "wrong-password"})
	if detailOf(t, err).GetCode() != CodeInvalidCredentials {
		t.Fatalf("wrong password on a revoked device = %v, want %s", err, CodeInvalidCredentials)
	}
}

// device/trust-per-user-device: one browser (one key) shared by two accounts
// is two devices. The first account's trust does not reach the second, which
// is asked for the second factor as any new device is.
func TestSignIn_TrustIsPerUserAndDeviceOnASharedDevice(t *testing.T) {
	seen := noSecondFactor(t)
	m, h := newSignInStore(t, "alice", "bob")
	m.put("alice", testJKT, &pb.Device{TrustedAt: timestamppb.Now()})

	for _, who := range []string{"alice", "bob"} {
		if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: who + "@example.com", Password: devicePassword}); err != nil {
			t.Fatalf("%s: %v", who, err)
		}
	}
	if len(*seen) != 2 || !(*seen)[0] || (*seen)[1] {
		t.Fatalf("trust handed to the second-factor gate = %v, want [alice trusted, bob not]", *seen)
	}
	if a, b := m.rows[devKey("alice", testJKT)], m.rows[devKey("bob", testJKT)]; a == nil || b == nil || a.GetId() == b.GetId() {
		t.Fatalf("one key, two accounts must be two rows: alice %+v, bob %+v", a, b)
	}
	if len(m.issued) != 2 || m.issued[0].GetDeviceId() == m.issued[1].GetDeviceId() {
		t.Fatalf("both sessions bound to one row: %+v", m.issued)
	}
	// Only alice's trust was renewed; bob's row was never trusted.
	if len(m.trusted) != 1 || m.trusted[0].GetUserId() != "alice" {
		t.Fatalf("TrustDevice = %+v, want alice's renewal only", m.trusted)
	}
}

// A password sign-in that met no second factor renews the trust of a device
// that already has it, and grants none to a device that does not.
func TestSignIn_RenewsDeviceTrustButNeverGrantsIt(t *testing.T) {
	noSecondFactor(t)
	for _, c := range []struct {
		name    string
		device  *pb.Device
		renewed bool
	}{
		{"untrusted device", &pb.Device{}, false},
		{"trusted device", &pb.Device{TrustedAt: timestamppb.Now()}, true},
	} {
		m, h := newSignInStore(t, "u1")
		m.put("u1", testJKT, c.device)
		if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(m.trusted) == 1; got != c.renewed {
			t.Errorf("%s: renewed = %v (%+v), want %v", c.name, got, m.trusted, c.renewed)
		}
	}
}

// After a password change or a disable, the device's earlier trust is not
// renewed by the password alone.
func TestSignIn_DoesNotRenewRevokedDeviceTrust(t *testing.T) {
	noSecondFactor(t)
	m, h := newSignInStore(t, "u1")
	m.put("u1", testJKT, &pb.Device{TrustedAt: timestamppb.New(time.Now().Add(-time.Hour))})
	m.revokedAt = timestamppb.Now()
	resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if err != nil || resp.GetToken() == "" {
		t.Fatalf("the sign-in itself must succeed: %v", err)
	}
	if len(m.trusted) != 0 {
		t.Errorf("revoked trust was renewed: %+v", m.trusted)
	}
}

// A sign-in that read the revocation stamp and lost the race to a revocation
// committing before its TrustDevice does not write trust past it.
func TestSignIn_ARevocationCommittedMidSignInIsNotOverwritten(t *testing.T) {
	noSecondFactor(t)
	seenStamp := timestamppb.New(time.Now().Add(-2 * time.Hour))
	for _, c := range []struct {
		name      string
		revokedAt *timestamppb.Timestamp
		later     *timestamppb.Timestamp
		wantCut   *timestamppb.Timestamp
		renewed   bool
	}{
		{"no revocation in flight", seenStamp, nil, seenStamp, true},
		{"never revoked, then revoked in flight", nil, timestamppb.Now(), neverRevoked, false},
		{"revoked before, then again in flight", seenStamp, timestamppb.Now(), seenStamp, false},
	} {
		m, h := newSignInStore(t, "u1")
		m.put("u1", testJKT, &pb.Device{TrustedAt: timestamppb.New(time.Now().Add(-time.Hour))})
		m.revokedAt, m.revokedLater = c.revokedAt, c.later
		resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
		if err != nil || resp.GetToken() == "" {
			t.Fatalf("%s: the sign-in itself must succeed: %v", c.name, err)
		}
		if renewed := len(m.trusted) == 1; renewed != c.renewed {
			t.Errorf("%s: renewed = %v (%+v), want %v", c.name, renewed, m.trusted, c.renewed)
		}
		if c.renewed && !proto.Equal(m.trusted[0].GetNotRevokedAfter(), c.wantCut) {
			t.Errorf("%s: cutoff = %v, want the stamp the sign-in read (%v)", c.name, m.trusted[0].GetNotRevokedAfter(), c.wantCut)
		}
	}
}

// Trust is best effort: a failed trust write does not fail the session.
func TestSignIn_AFailedTrustWriteStillSignsIn(t *testing.T) {
	noSecondFactor(t)
	m, h := newSignInStore(t, "u1")
	m.put("u1", testJKT, &pb.Device{TrustedAt: timestamppb.Now()})
	m.trustErr = status.Error(codes.Unavailable, "db down")
	resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if err != nil {
		t.Fatalf("a failed trust write failed the sign-in: %v", err)
	}
	if resp.GetToken() == "" || len(m.issued) != 1 || m.issued[0].GetTokenHash() != sha256Hex(resp.GetToken()) {
		t.Fatalf("no session issued: %+v (IssueToken %+v)", resp, m.issued)
	}
}

// ── the other mint paths refuse without a proof, spending nothing ──

// nothingStore panics on any storage call (its embedded clients are nil), so a
// handler refused before touching storage is what passes.
type nothingStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
}

// device/no-unbound-credential for every mint path: no proof, no token — and
// nothing single-use is spent on the way (a confirmation attempt, an MFA
// attempt, an OAuth login code, a CLI code), nor a password hashed.
func TestEveryMintPath_RefusesWithoutAProofBeforeTouchingStorage(t *testing.T) {
	// SignUp that issues a session (no sign_up_confirmation): the one that
	// needs the proof. The parked registration issues none.
	savedConfirm := signUpConfirmation
	signUpConfirmation = nil
	t.Cleanup(func() { signUpConfirmation = savedConfirm })

	h := &AuthServiceHandler{Query: nothingStore{}, Mutation: nothingStore{}, PasswordHash: testPasswordSettings()}
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"SignIn": func() error {
			_, err := h.SignIn(ctx, &pb.SignInReq{Email: "a@example.com", Password: devicePassword})
			return err
		},
		"SignUp": func() error {
			_, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: devicePassword})
			return err
		},
		"ConfirmSignUp": func() error {
			_, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: "p1", Code: "ABCD2345"})
			return err
		},
		"VerifyMfa": func() error {
			_, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "c1", Code: "123456"})
			return err
		},
		"OAuthExchange": func() error {
			_, err := h.OAuthExchange(ctx, &pb.OAuthExchangeReq{Code: "code", CodeVerifier: strings.Repeat("v", 43)})
			return err
		},
		"CliToken": func() error {
			_, err := h.CliToken(ctx, &pb.CliTokenReq{Code: "code", CodeVerifier: strings.Repeat("v", 43)})
			return err
		},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s reached storage without a proof: %v", name, r)
				}
			}()
			err := call()
			if detailOf(t, err).GetCode() != CodeDeviceProofRequired {
				t.Errorf("%s without a proof: err = %v, want %s", name, err, CodeDeviceProofRequired)
			}
		}()
	}
}

// ── Authenticate: the binding check ─────────────────────────

// bindingQuery resolves one token to a principal bound to `thumb` (revoked
// at `revoked`), through either resolver.
type bindingQuery struct {
	pb.AuthQueryClient
	thumb   string
	revoked *timestamppb.Timestamp
	known   string // the only token that resolves
}

func (q *bindingQuery) GetUserByTokenWithPermissions(_ context.Context, in *pb.GetUserByTokenWithPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	if in.GetTokenHash() != sha256Hex(q.known) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserByTokenWithPermissionsResp{User: &pb.User{Id: "u1"}, TokenId: "tok-1", StoredTokenHash: in.GetTokenHash(),
		DeviceThumbprint: q.thumb, DeviceRevokedAt: q.revoked}, nil
}

func (q *bindingQuery) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	if in.GetTokenHash() != sha256Hex(q.known) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "tok-1", TokenType: pb.TokenType_TOKEN_TYPE_SESSION, StoredTokenHash: in.GetTokenHash(),
		User: &pb.User{Id: "u1"}, LastUsedAt: timestamppb.Now(), DeviceThumbprint: q.thumb, DeviceRevokedAt: q.revoked}, nil
}

func (q *bindingQuery) GetExpiredToken(context.Context, *pb.GetExpiredTokenReq, ...grpc.CallOption) (*pb.GetExpiredTokenResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

func (q *bindingQuery) GetExpiredTokenWithType(context.Context, *pb.GetExpiredTokenWithTypeReq, ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

func (q *bindingQuery) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (q *bindingQuery) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

// bindingAuthenticate runs Authenticate through one resolver with no feature
// decorators or narrowers: what is under test is the binding check.
func bindingAuthenticate(t *testing.T, resolver func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error), q *bindingQuery, req *pb.AuthReq) (*pb.AuthResp, error) {
	t.Helper()
	prevDec, prevNarrow, prevRes := scopeDecorators, grantNarrowers, resolvePrincipal
	t.Cleanup(func() { scopeDecorators, grantNarrowers, resolvePrincipal = prevDec, prevNarrow, prevRes })
	scopeDecorators, grantNarrowers, resolvePrincipal = nil, nil, resolver
	h := &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}, HeaderName: "Authorization", Scheme: "Bearer"}
	return h.Authenticate(context.Background(), req)
}

var resolvers = map[string]func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error){
	"session":     resolvePrincipalSession,
	"realm-aware": resolvePrincipalRealmAware,
}

func TestAuthenticate_ABoundTokenWithItsKeyPassesAndNamesTheDevice(t *testing.T) {
	for name, res := range resolvers {
		resp, err := bindingAuthenticate(t, res, &bindingQuery{thumb: testJKT, known: "tok"}, boundAuthReq("tok", testJKT))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if resp.GetDeviceId() != testJKT || resp.GetUserId() != "u1" {
			t.Errorf("%s: AuthResp = %+v, want device_id = the bound thumbprint", name, resp)
		}
	}
}

// Every refusal of the binding check, through both resolvers.
func TestAuthenticate_RefusesWhatTheBindingDoesNotAllow(t *testing.T) {
	revoked := timestamppb.Now()
	for _, c := range []struct {
		name  string
		thumb string
		rev   *timestamppb.Timestamp
		req   *pb.AuthReq
		code  string
	}{
		// device/proof-required: a bound token without a proof.
		{"no proof", testJKT, nil, &pb.AuthReq{Headers: map[string]string{"authorization": "DPoP tok"}}, CodeDeviceProofRequired},
		{"a malformed proof thumbprint", testJKT, nil, boundAuthReq("tok", "short"), CodeDeviceProofRequired},
		// A bound token presented as Bearer is refused even next to a proof:
		// a downgrade is never ambiguous.
		{"presented as Bearer", testJKT, nil, &pb.AuthReq{Headers: map[string]string{"authorization": "Bearer tok", dpopJKTKey: testJKT}}, CodeDeviceProofRequired},
		// The one-off introduction: a token minted before binding is refused.
		{"a legacy unbound token", "", nil, boundAuthReq("tok", testJKT), CodeDeviceProofRequired},
		{"a proof by another key", testJKT, nil, boundAuthReq("tok", otherJKT), CodeDeviceMismatch},
		// device/revoked-refused-for-good: said only to the key's holder…
		{"a revoked device, its own key", testJKT, revoked, boundAuthReq("tok", testJKT), CodeDeviceRevoked},
		// …anyone else hears only that the key is not the bound one.
		{"a revoked device, another key", testJKT, revoked, boundAuthReq("tok", otherJKT), CodeDeviceMismatch},
	} {
		for name, res := range resolvers {
			_, err := bindingAuthenticate(t, res, &bindingQuery{thumb: c.thumb, revoked: c.rev, known: "tok"}, c.req)
			t.Run(c.name+"/"+name, func(t *testing.T) { wantDeviceRefusal(t, err, c.code) })
		}
	}
}

// An unknown token stays the opaque refusal: the binding check runs only on a
// token that resolved, so none of its codes says whether a token exists.
func TestAuthenticate_AnUnknownTokenStaysOpaqueWhateverTheProof(t *testing.T) {
	for name, res := range resolvers {
		_, err := bindingAuthenticate(t, res, &bindingQuery{thumb: testJKT, known: "tok"}, boundAuthReq("other", otherJKT))
		st, _ := status.FromError(err)
		if st.Code() != codes.Unauthenticated || len(st.Details()) != 0 {
			t.Errorf("%s: unknown token = %v with %d details, want the bare opaque refusal", name, err, len(st.Details()))
		}
	}
}

// ── the statements ──────────────────────────────────────────

func queryRPCBody(t *testing.T, rpc string) string {
	t.Helper()
	raw, err := os.ReadFile("../../proto/queries/auth_query.proto")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "rpc "+rpc+"(")
	if i < 0 {
		t.Fatalf("%s not found", rpc)
	}
	end := strings.Index(src[i:], "\n  }\n")
	return src[i : i+end]
}

// One UPSERT keyed on the unique (user_id, thumbprint) pair — no
// read-then-insert race — that answers revoked_at and trusted_at, so a mint can
// refuse a revoked device and decide trust without another round trip.
func TestRegisterDevice_IsOneUpsertOnTheUserDevicePair(t *testing.T) {
	body := mutationRPCBody(t, "RegisterDevice")
	for _, want := range []string{
		`"UPSERT INTO @module.Device SET "`,
		`"ON CONFLICT (user_id, thumbprint) DO UPDATE SET "`,
		`"          revoked_at AS device.revoked_at"`,
		`"          trusted_at AS device.trusted_at, "`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("RegisterDevice lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "revoked_at = ") {
		t.Errorf("RegisterDevice must never write revoked_at (a revoked device is never revived):\n%s", body)
	}
}

// The guard lives in the statement, so a revocation that commits between the
// handler's read and the write is seen by the write itself — and a revoked
// device is never trusted.
func TestTrustDevice_TheStatementIsGuardedByTheRevocations(t *testing.T) {
	body := mutationRPCBody(t, "TrustDevice")
	for _, want := range []string{
		`"WHERE id = :device_id AND user_id = :user_id AND revoked_at IS NULL "`,
		`"AND NOT EXISTS (SELECT u.id FROM @module.User u "`,
		`"WHERE u.id = :user_id AND u.device_trust_revoked_at > :not_revoked_after) "`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("TrustDevice lacks %s:\n%s", want, body)
		}
	}
}

// Every session row is written with its device, and both token lookups read
// the binding with the token, so the check costs no round trip.
func TestTokenStatements_CarryTheBinding(t *testing.T) {
	if body := mutationRPCBody(t, "IssueToken"); !strings.Contains(body, `"device_id = :device_id "`) || strings.Contains(body, "feature(devices)") {
		t.Errorf("IssueToken does not always write the device:\n%s", body)
	}
	for _, rpc := range []string{"GetUserByTokenWithPermissions", "GetTokenWithType"} {
		body := queryRPCBody(t, rpc)
		for _, want := range []string{
			`"LEFT JOIN @module.Device d ON d.id = t.device_id "`,
			`COALESCE(d.thumbprint, '') AS device_thumbprint`,
			`d.revoked_at AS device_revoked_at`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s:\n%s", rpc, want, body)
			}
		}
	}
}

// A session cannot even be requested unbound: IssueTokenReq.device_id is
// required (no `null: true`), so the request validation refuses one without it.
func TestIssueTokenReq_RequiresTheDevice(t *testing.T) {
	raw, err := os.ReadFile("../../proto/mutations/auth_mutation.proto")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "message IssueTokenReq {")
	j := strings.Index(src[i:], "\n}\n")
	msg := src[i : i+j]
	if !strings.Contains(msg, `string device_id = 3 [(w17.field) = { type: UUID }];`) {
		t.Errorf("IssueTokenReq.device_id is not a required UUID:\n%s", msg)
	}
}

// device/revocation-is-a-state for devices: revoking writes revoked_at; no
// statement deletes a Device row a sign-in could then re-create.
func TestMarkDeviceRevoked_IsAnUpdateNeverADelete(t *testing.T) {
	body := mutationRPCBody(t, "MarkDeviceRevoked")
	if !strings.Contains(body, `"UPDATE @module.Device SET revoked_at = NOW() "`) ||
		!strings.Contains(body, `"WHERE id = :device_id AND user_id = :user_id AND revoked_at IS NULL "`) {
		t.Errorf("MarkDeviceRevoked is not an owner-guarded, first-revocation-wins UPDATE:\n%s", body)
	}
	raw, err := os.ReadFile("../../proto/mutations/auth_mutation.proto")
	if err != nil {
		t.Fatal(err)
	}
	for _, rpc := range []string{"DeleteDevice", "CreateDevice", "TouchDevice"} {
		if strings.Contains(string(raw), "rpc "+rpc+"(") {
			t.Errorf("%s is still declared", rpc)
		}
	}
}

// ── API tokens: refused rather than minted unbound ──────────

// mintAPITokensUnbound lifts apiTokenBindingGate for a test of the API-token
// minting machinery underneath it (the transaction, the subset, the expiry,
// the bot checks), which stays the path the bound mint will take.
func mintAPITokensUnbound(t *testing.T) {
	t.Helper()
	saved := apiTokenBindingGate
	apiTokenBindingGate = func(context.Context) error { return nil }
	t.Cleanup(func() { apiTokenBindingGate = saved })
}

// device/no-unbound-credential for API tokens: until a request can carry the
// key of the program that will use the token, none is minted — and the
// refusal says why, with nothing written.
func TestApiTokens_AreRefusedUntilTheyCanBeBound(t *testing.T) {
	m := &apiTokenMgmtMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	_, err := h.CreateApiToken(ctxWithCaller("u1"), &pb.CreateApiTokenReq{Name: "ci"})
	if status.Code(err) != codes.Unimplemented || detailOf(t, err).GetCode() != CodeDeviceKeyRequired {
		t.Fatalf("CreateApiToken = %v, want Unimplemented/%s", err, CodeDeviceKeyRequired)
	}
	if m.issueReq != nil {
		t.Fatalf("an API token was minted unbound: %+v", m.issueReq)
	}

	// The one minting path IssueBotToken shares refuses the same way.
	if _, _, err := h.issueApiTokenTx(context.Background(), "bot-1", "deploy", nil, nil); detailOf(t, err).GetCode() != CodeDeviceKeyRequired {
		t.Fatalf("issueApiTokenTx = %v, want %s", err, CodeDeviceKeyRequired)
	}
	if m.issueReq != nil {
		t.Fatalf("a bot token was minted unbound: %+v", m.issueReq)
	}
}

// device/label-is-display-only: a long multi-byte header is cut on a rune
// boundary, never into invalid UTF-8 (which would fail the proto marshal and
// with it the sign-in).
func TestTruncate_CutsOnARuneBoundary(t *testing.T) {
	s := strings.Repeat("a", 254) + "é" // é is two bytes: 254 + 2 = 256 > 255
	if got := truncate(s, maxLabelLen); got != strings.Repeat("a", 254) {
		t.Fatalf("truncate cut inside a rune: %q", got[len(got)-3:])
	}
	if got := truncate("short", maxLabelLen); got != "short" {
		t.Fatalf("a short value changed: %q", got)
	}
	if got := truncate("203.0.113.7, 10.0.0.1", 45); got != "203.0.113.7, 10.0.0.1" {
		t.Fatalf("got %q", got)
	}
}
