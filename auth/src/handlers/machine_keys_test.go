package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// API tokens and machine-account tokens bound to a public key the request
// names (CreateApiToken, IssueBotToken).

// Two program keys as public JWKs, with their RFC 7638 thumbprints: the P-256
// key of the RFC 9449 examples (its jkt, RFC 9449 §6.1, is otherJKT) and the
// Ed25519 key of RFC 8037 Appendix A (thumbprint from A.3).
const (
	p256JWK    = `{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}`
	p256JKT    = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	ed25519JWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	ed25519JKT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	// privateD is the private scalar a careless client pastes beside the
	// public half; it must appear nowhere it is refused.
	privateD = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
)

// keyStore is the Device table (deviceStore: one row per (user, thumbprint),
// RegisterDevice's UPSERT) plus the API-token writes and the machine-account
// reads an API-token mint makes, in the order it makes them.
type keyStore struct {
	*deviceStore

	minted []*pb.IssueApiTokenReq
	// IssueBotBearerToken's writes (device/bot-bearer)
	bearerMinted []*pb.IssueBotBearerTokenReq
	order        []string
	bot          *pb.User
	// a machine account's ListMachineKeys failure
	keysErr error
	// sessions: token id → the device that approved it (a CLI session's
	// browser), as GetSessionApprover reads UserToken.approved_by_device_id
	approvers map[string]string
}

func (s *keyStore) GetSessionApprover(_ context.Context, in *pb.GetSessionApproverReq, _ ...grpc.CallOption) (*pb.GetSessionApproverResp, error) {
	return &pb.GetSessionApproverResp{ApprovedByDeviceId: s.approvers[in.GetTokenId()]}, nil
}

func newKeyStore() *keyStore {
	return &keyStore{deviceStore: newDeviceStore(), bot: &pb.User{Id: "bot-1", Email: "ci@machines.example", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"}}
}

func (s *keyStore) RegisterDevice(ctx context.Context, in *pb.RegisterDeviceReq, o ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	s.order = append(s.order, "register")
	return s.deviceStore.RegisterDevice(ctx, in, o...)
}

func (s *keyStore) IssueApiToken(_ context.Context, in *pb.IssueApiTokenReq, _ ...grpc.CallOption) (*pb.IssueApiTokenResp, error) {
	s.order = append(s.order, "mint")
	s.minted = append(s.minted, in)
	return &pb.IssueApiTokenResp{Token: &pb.UserToken{Id: "tok-api", UserId: in.GetUserId(), DeviceId: in.GetDeviceId()}}, nil
}

func (s *keyStore) AddTokenPermission(context.Context, *pb.AddTokenPermissionReq, ...grpc.CallOption) (*pb.AddTokenPermissionResp, error) {
	return &pb.AddTokenPermissionResp{}, nil
}

// GetUserDeviceByThumbprint mirrors its statement: the live row of the pair.
func (s *keyStore) GetUserDeviceByThumbprint(_ context.Context, in *pb.GetUserDeviceByThumbprintReq, _ ...grpc.CallOption) (*pb.GetUserDeviceByThumbprintResp, error) {
	d, ok := s.rows[devKey(in.GetUserId(), in.GetThumbprint())]
	if !ok || d.GetRevokedAt() != nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserDeviceByThumbprintResp{DeviceId: d.GetId()}, nil
}

func (s *keyStore) LockMachineAccount(_ context.Context, in *pb.LockMachineAccountReq, _ ...grpc.CallOption) (*pb.LockMachineAccountResp, error) {
	s.order = append(s.order, "lock")
	return &pb.LockMachineAccountResp{UserId: in.GetUserId()}, nil
}

// ListMachineKeys mirrors its statement: the account's live keyed devices.
func (s *keyStore) ListMachineKeys(_ context.Context, in *pb.ListMachineKeysReq, _ ...grpc.CallOption) (*pb.ListMachineKeysResp, error) {
	s.order = append(s.order, "keys")
	if s.keysErr != nil {
		return nil, s.keysErr
	}
	var out []*pb.MachineKey
	for _, d := range s.rows {
		if d.GetUserId() == in.GetUserId() && d.GetRevokedAt() == nil && d.GetThumbprint() != "" {
			out = append(out, &pb.MachineKey{Id: d.GetId(), Thumbprint: d.GetThumbprint()})
		}
	}
	return &pb.ListMachineKeysResp{Keys: out}, nil
}

// The machine account, holding no role (the ceiling has nothing to refuse).
func (s *keyStore) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	if in.GetUserId() != s.bot.GetId() {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserByIdResp{User: proto.Clone(s.bot).(*pb.User)}, nil
}

func (s *keyStore) GetUserRoleGrants(context.Context, *pb.GetUserRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{}, nil
}

func (s *keyStore) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	return &pb.ListRoleGrantsResp{}, nil
}

// operatorCtx is a signed-in operator of a realm without organizations whose
// request was proved with the key jkt ("" = none), as Authenticate leaves it.
func operatorCtx(uid, jkt string) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: "session-" + uid, DeviceId: jkt})
	if err != nil {
		panic(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid, "x-w17-scope-tenant_id", "tenant-1",
		userMetadataKey, base64.StdEncoding.EncodeToString(raw),
		forwardedUserAgentMetadataKey, historyUA, clientIPMetadataKey, historyIP))
}

// wantKeyRefusal asserts err is the refusal of the request's key: code c with
// detail code, on the public_key field, and NOT Unauthenticated with an
// ErrorInfo — a client reads those as "my own device is gone" and discards
// its key.
func wantKeyRefusal(t *testing.T, err error, c codes.Code, code string) {
	t.Helper()
	st := status.Convert(err)
	if err == nil || st.Code() != c {
		t.Fatalf("err = %v, want %v/%s", err, c, code)
	}
	ed := detailOf(t, err)
	if ed.GetCode() != code || ed.GetField() != "public_key" || ed.GetMessage() == "" {
		t.Fatalf("ErrorDetail = %v, want %s on public_key with a sentence", ed, code)
	}
	if len(st.Details()) != 1 {
		t.Fatalf("details = %v, want the ErrorDetail alone", st.Details())
	}
}

// device/no-unbound-credential for API tokens: the token is bound to the
// (caller, thumbprint) Device of the key the request names — computed by the
// handler, RFC 7638 — for both key types; the device is labelled after the
// token and has no client address (the creating request's is not the
// program's); the response names the binding.
func TestCreateApiToken_BindsTheTokenToTheGivenKey(t *testing.T) {
	for jwk, jkt := range map[string]string{p256JWK: p256JKT, ed25519JWK: ed25519JKT} {
		s := newKeyStore()
		h := &AuthServiceHandler{Query: s, Mutation: s}
		resp, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "deploy", PublicKey: jwk})
		if err != nil {
			t.Fatalf("%s: %v", jkt, err)
		}
		dev := s.rows[devKey("u1", jkt)]
		if dev == nil || len(s.minted) != 1 {
			t.Fatalf("%s: device %v, minted %v", jkt, dev, s.minted)
		}
		if got := s.minted[0]; got.GetDeviceId() != dev.GetId() || got.GetUserId() != "u1" || got.GetTokenType() != pb.TokenType_TOKEN_TYPE_API {
			t.Errorf("%s: minted %+v, want bound to %s", jkt, got, dev.GetId())
		}
		if dev.GetLabel() != "API token: deploy" || dev.GetIp() != "" {
			t.Errorf("%s: device label/ip = %q/%q", jkt, dev.GetLabel(), dev.GetIp())
		}
		if resp.GetDeviceId() != jkt {
			t.Errorf("response device_id = %q, want %s", resp.GetDeviceId(), jkt)
		}
	}
}

// No key, no token: DEVICE_KEY_REQUIRED on the field, nothing registered or
// minted.
func TestCreateApiToken_WithoutAKeyMintsNothing(t *testing.T) {
	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci"})
	wantKeyRefusal(t, err, codes.InvalidArgument, CodeDeviceKeyRequired)
	if len(s.registered) != 0 || len(s.minted) != 0 {
		t.Fatalf("registered %v, minted %v", s.registered, s.minted)
	}
}

// Only a public P-256 or Ed25519 JWK binds: another key type or curve, a
// point off the curve, a malformed JWK are DEVICE_KEY_INVALID, with nothing
// registered or minted.
func TestCreateApiToken_RefusesAKeyThatIsNotAPublicDeviceKey(t *testing.T) {
	for name, jwk := range map[string]string{
		"RSA":           `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt","e":"AQAB"}`,
		"P-384":         `{"kty":"EC","crv":"P-384","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}`,
		"X25519":        `{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"off the curve": `{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDE"}`,
		"not JSON":      `not a key`,
		"a thumbprint":  p256JKT,
	} {
		s := newKeyStore()
		h := &AuthServiceHandler{Query: s, Mutation: s}
		_, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci", PublicKey: jwk})
		t.Run(name, func(t *testing.T) { wantKeyRefusal(t, err, codes.InvalidArgument, CodeDeviceKeyInvalid) })
		if len(s.registered) != 0 || len(s.minted) != 0 {
			t.Fatalf("%s: registered %v, minted %v", name, s.registered, s.minted)
		}
	}
}

// device/private-key-never-leaves: a JWK carrying its private half is refused
// with the sentence that says so, and the private scalar is stored nowhere —
// no device, no token, not the history row — and appears in no answer and no
// log line, also when the history write fails and is logged.
func TestCreateApiToken_APrivateKeyIsRefusedNeitherStoredNorLogged(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	jwk := strings.TrimSuffix(p256JWK, "}") + `,"d":"` + privateD + `"}`
	for _, failHistory := range []bool{false, true} {
		s := newKeyStore()
		h := &AuthServiceHandler{Query: s, Mutation: s}
		hist := keepHistory(h)
		if failHistory {
			hist.err = status.Error(codes.Unavailable, "history down")
		}
		_, err := h.CreateApiToken(operatorCtx("u1", testJKT), &pb.CreateApiTokenReq{Name: "ci", PublicKey: jwk})
		wantKeyRefusal(t, err, codes.InvalidArgument, CodeDeviceKeyInvalid)
		if detailOf(t, err).GetMessage() != MsgClientKeyPrivate {
			t.Errorf("the refusal does not say the key is private: %q", detailOf(t, err).GetMessage())
		}
		if len(s.registered) != 0 || len(s.minted) != 0 {
			t.Fatalf("registered %v, minted %v", s.registered, s.minted)
		}
		if strings.Contains(status.Convert(err).Proto().String(), privateD) {
			t.Errorf("the answer repeats the private key: %v", err)
		}
		for _, r := range hist.rows {
			if strings.Contains(r.String(), privateD) || r.GetThumbprint() != "" {
				t.Errorf("the history row carries the key: %v", r)
			}
			if r.GetOutcome() != pb.SignInOutcome_SIGN_IN_OUTCOME_KEY_REFUSED {
				t.Errorf("outcome = %v, want KEY_REFUSED", r.GetOutcome())
			}
		}
	}
	if !strings.Contains(logged.String(), "sign-in history row not written") {
		t.Fatalf("the failed history write was not logged, so the log was not exercised:\n%s", logged.String())
	}
	if strings.Contains(logged.String(), privateD) || strings.Contains(logged.String(), "l8tFrhx") {
		t.Errorf("a log line carries the key:\n%s", logged.String())
	}
}

// A key of a device the owner revoked is refused for good — as a sign-in with
// it would be — but as the request's key (FailedPrecondition,
// DEVICE_KEY_REVOKED), never as the caller's own device: nothing is minted.
func TestCreateApiToken_ARevokedKeyIsRefused(t *testing.T) {
	s := newKeyStore()
	s.put("u1", p256JKT, &pb.Device{ApiKey: true, RevokedAt: timestamppb.Now()})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	hist := keepHistory(h)
	_, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci", PublicKey: p256JWK})
	wantKeyRefusal(t, err, codes.FailedPrecondition, CodeDeviceKeyRevoked)
	if len(s.minted) != 0 {
		t.Fatalf("a token was minted for a revoked key: %v", s.minted)
	}
	if len(hist.rows) != 1 || hist.rows[0].GetOutcome() != pb.SignInOutcome_SIGN_IN_OUTCOME_DEVICE_REVOKED ||
		hist.rows[0].GetDeviceId() != s.rows[devKey("u1", p256JKT)].GetId() || hist.rows[0].GetThumbprint() != p256JKT {
		t.Errorf("history = %v, want one DEVICE_REVOKED row naming the revoked device", hist.rows)
	}
}

// A key is a program's or a signed-in client's, never both (Device.api_key).
// The key of a device that signs in to the account is refused for an API
// token — the creating browser's own key above all, the binding the spec
// calls useless to the script — and nothing is minted.
func TestCreateApiToken_RefusesTheKeyOfADeviceThatSignsIn(t *testing.T) {
	s := newKeyStore()
	s.put("u1", p256JKT, &pb.Device{})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.CreateApiToken(operatorCtx("u1", p256JKT), &pb.CreateApiTokenReq{Name: "ci", PublicKey: p256JWK})
	wantKeyRefusal(t, err, codes.InvalidArgument, CodeDeviceKeyInvalid)
	if detailOf(t, err).GetMessage() != MsgClientKeySignsIn || len(s.minted) != 0 {
		t.Fatalf("detail %v, minted %v", detailOf(t, err), s.minted)
	}
	// Registered as a program's key, it stays one: the next token reuses it.
	if _, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci", PublicKey: ed25519JWK}); err != nil {
		t.Fatal(err)
	}
	if !s.rows[devKey("u1", ed25519JKT)].GetApiKey() {
		t.Fatal("the program's device is not marked api_key")
	}
}

// …and a program's key never signs in: every sign-in mint (mintDevice)
// refuses it with the opaque refusal, so no session lives on a device the
// owner's device management does not list.
func TestSignIn_AProgramKeyDoesNotSignIn(t *testing.T) {
	s := newDeviceStore()
	prog := s.put("u1", testJKT, &pb.Device{ApiKey: true})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	dev, err := mintDevice(mintCtx(), h, "u1", testJKT)
	if err == nil || !errors.Is(err, errDeviceIsAProgramKey) || dev.id != prog.GetId() {
		t.Fatalf("mintDevice = %+v, %v; want the program-key refusal naming the device", dev, err)
	}
	if len(s.issued) != 0 {
		t.Fatal("a session was issued")
	}
	// The same key for another account is that account's device, not a program's.
	if _, err := mintDevice(mintCtx(), h, "u2", testJKT); err != nil {
		t.Fatalf("another account's pair: %v", err)
	}
}

// The owner's device management lists signed-in devices only, so "sign out
// everywhere else" leaves API tokens alone (devices/revoke-all-spares-api-tokens);
// and revoking the device an API token was created from ends the CLI
// sessions it approved, never the API tokens it created.
func TestDeviceManagement_LeavesAPITokensAlone(t *testing.T) {
	if body := queryRPCBody(t, "ListUserDevices"); !strings.Contains(body, `AND d.api_key = FALSE`) {
		t.Errorf("ListUserDevices lists programs' keys:\n%s", body)
	}
	body := mutationRPCBody(t, "RevokeDeviceTokens")
	approved, _, _ := strings.Cut(body[strings.Index(body, `name: "approved"`):], `name: "main"`)
	if !strings.Contains(approved, `"AND ?feature(api_token) token_type = 1"`) {
		t.Errorf("the approved op revokes API tokens the device created:\n%s", approved)
	}
}

// The creating caller's own device — the key its request was proved with —
// is recorded on the token as its approver; a request with no device records
// none.
func TestCreateApiToken_RecordsTheCreatorsDevice(t *testing.T) {
	s := newKeyStore()
	browser := s.put("u1", testJKT, &pb.Device{})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.CreateApiToken(operatorCtx("u1", testJKT), &pb.CreateApiTokenReq{Name: "ci", PublicKey: p256JWK}); err != nil {
		t.Fatal(err)
	}
	if got := s.minted[0]; got.GetApprovedByDeviceId() != browser.GetId() || got.GetDeviceId() == browser.GetId() {
		t.Errorf("minted %+v, want bound to the program's device and approved by the browser's %s", got, browser.GetId())
	}
	if _, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci", PublicKey: p256JWK}); err != nil {
		t.Fatal(err)
	}
	if got := s.minted[1].GetApprovedByDeviceId(); got != "" {
		t.Errorf("a request with no device recorded approver %q", got)
	}
}

// device/sign-in-history: an issuance is one row, method API_TOKEN, naming
// the owner, the bound device and its key, and the creating request's client
// — the success row written in the transaction that mints the token.
func TestCreateApiToken_IsRecordedInTheHistory(t *testing.T) {
	s := newKeyStore()
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: s, Mutation: s, DistTx: tx, Connection: "app-postgres"}
	hist := keepHistory(h)
	if _, err := h.CreateApiToken(operatorCtx("u1", testJKT), &pb.CreateApiTokenReq{Name: "ci", PublicKey: ed25519JWK}); err != nil {
		t.Fatal(err)
	}
	hist.one(t, "CreateApiToken", want{
		method: pb.SignInMethod_SIGN_IN_METHOD_API_TOKEN, outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK,
		user: "u1", device: s.rows[devKey("u1", ed25519JKT)].GetId(), thumb: ed25519JKT,
	})
	if hist.txIDs[0] == "" || tx.settled() != "committed" {
		t.Errorf("the success row was written outside the minting transaction (tx %q, %s)", hist.txIDs[0], tx.settled())
	}
}

// ── machine accounts: one key (device/bot-one-key) ──────────────────────

// The first token registers the machine account's key as its one device; a
// second with the same key (another replica) reuses that device; a token with
// another key is refused (BOT_KEY_MISMATCH) and mints nothing — until the
// device is revoked, after which a new key becomes the account's one key. The
// account row is locked before its key is read.
func TestIssueBotToken_OneKeyPerMachineAccount(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	op := operatorCtx("op-1", testJKT)
	issue := func(jwk string) (*pb.IssueBotTokenResp, error) {
		return h.IssueBotToken(op, &pb.IssueBotTokenReq{UserId: "bot-1", Name: "replica", PublicKey: jwk})
	}

	first, err := issue(p256JWK)
	if err != nil {
		t.Fatalf("first key: %v", err)
	}
	dev := s.rows[devKey("bot-1", p256JKT)]
	if first.GetDeviceId() != p256JKT || s.minted[0].GetDeviceId() != dev.GetId() || s.minted[0].GetUserId() != "bot-1" {
		t.Fatalf("first token %+v / %+v, want bound to the bot's %s", first, s.minted[0], dev.GetId())
	}
	if dev.GetLabel() != machineKeyLabel {
		t.Errorf("label = %q", dev.GetLabel())
	}
	if strings.Join(s.order, ",") != "lock,keys,register,mint" {
		t.Errorf("order = %v, want the account locked before its key is read", s.order)
	}

	if _, err := issue(p256JWK); err != nil {
		t.Fatalf("the same key again (a replica): %v", err)
	}
	if s.minted[1].GetDeviceId() != dev.GetId() || len(s.rows) != 1 {
		t.Fatalf("the same key made another device: %v", s.rows)
	}

	_, err = issue(ed25519JWK)
	wantKeyRefusal(t, err, codes.FailedPrecondition, CodeBotKeyMismatch)
	if len(s.minted) != 2 || s.rows[devKey("bot-1", ed25519JKT)] != nil {
		t.Fatalf("a second key was registered or minted for: rows %v, minted %d", s.rows, len(s.minted))
	}

	// Revoked, the old key is refused for good, and a new key replaces it.
	dev.RevokedAt = timestamppb.Now()
	_, err = issue(p256JWK)
	wantKeyRefusal(t, err, codes.FailedPrecondition, CodeDeviceKeyRevoked)
	if _, err := issue(ed25519JWK); err != nil {
		t.Fatalf("a new key after the old device was revoked: %v", err)
	}
	if s.minted[len(s.minted)-1].GetDeviceId() != s.rows[devKey("bot-1", ed25519JKT)].GetId() {
		t.Error("the new key's token is not bound to the new device")
	}
}

// The operator's own device is recorded as the approver of the machine
// account's token, and the issuance is one BOT_TOKEN row naming the machine
// account, its device and key.
func TestIssueBotToken_RecordsTheOperatorsDeviceAndTheHistory(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	laptop := s.put("op-1", testJKT, &pb.Device{})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	hist := keepHistory(h)
	if _, err := h.IssueBotToken(operatorCtx("op-1", testJKT), &pb.IssueBotTokenReq{UserId: "bot-1", PublicKey: p256JWK}); err != nil {
		t.Fatal(err)
	}
	if got := s.minted[0].GetApprovedByDeviceId(); got != laptop.GetId() {
		t.Errorf("approver = %q, want the operator's device %s", got, laptop.GetId())
	}
	hist.one(t, "IssueBotToken", want{
		method: pb.SignInMethod_SIGN_IN_METHOD_BOT_TOKEN, outcome: pb.SignInOutcome_SIGN_IN_OUTCOME_OK,
		user: "bot-1", address: "ci@machines.example", device: s.rows[devKey("bot-1", p256JKT)].GetId(), thumb: p256JKT,
	})
}

// The key is read after the authorization checks — a caller who may not mint
// for the account hears that, whatever key it sent — and a bad key mints
// nothing for a machine account either.
func TestIssueBotToken_RefusesABadKeyAfterTheChecks(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.IssueBotToken(operatorCtx("op-1", ""), &pb.IssueBotTokenReq{UserId: "nobody", PublicKey: "garbage"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an unknown account with a bad key: %v, want the account refusal", err)
	}
	// No key at all is a bearer token now (device/bot-bearer), not a refusal.
	for jwk, code := range map[string]string{`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"` + privateD + `"}`: CodeDeviceKeyInvalid} {
		_, err := h.IssueBotToken(operatorCtx("op-1", ""), &pb.IssueBotTokenReq{UserId: "bot-1", PublicKey: jwk})
		wantKeyRefusal(t, err, codes.InvalidArgument, code)
	}
	if len(s.registered) != 0 || len(s.minted) != 0 {
		t.Fatalf("registered %v, minted %v", s.registered, s.minted)
	}
}

// ── Authenticate: an API token is bound like a session ──────────────────

// apiTokenLookup resolves one API token bound to thumb ("" = unbound).
type apiTokenLookup struct {
	pb.AuthQueryClient
	known, thumb string
	lookups      int
}

func (q *apiTokenLookup) GetTokenWithType(_ context.Context, in *pb.GetTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	q.lookups++
	if in.GetTokenHash() != sha256Hex(q.known) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetTokenWithTypeResp{UserId: "u1", TokenId: "tok-api", TokenType: pb.TokenType_TOKEN_TYPE_API, StoredTokenHash: in.GetTokenHash(),
		User: &pb.User{Id: "u1"}, LastUsedAt: timestamppb.Now(), DeviceThumbprint: q.thumb}, nil
}

func (q *apiTokenLookup) GetExpiredTokenWithType(context.Context, *pb.GetExpiredTokenWithTypeReq, ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	return nil, status.Error(codes.NotFound, "no rows")
}

func (q *apiTokenLookup) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

func (q *apiTokenLookup) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	return &pb.GetTokenPermissionSubsetResp{}, nil
}

// device/proof-required for API tokens: no carve-out. Without a proof — or
// sent as Bearer — the request is refused before the lookup; with a proof by
// another key, or for a token minted unbound, it is the opaque refusal; only a
// proof by the bound key passes, and names the device.
func TestAuthenticate_AnAPITokenNeedsAProofByItsKey(t *testing.T) {
	prevDec, prevNarrow, prevRes := scopeDecorators, grantNarrowers, resolvePrincipal
	t.Cleanup(func() { scopeDecorators, grantNarrowers, resolvePrincipal = prevDec, prevNarrow, prevRes })
	scopeDecorators, grantNarrowers, resolvePrincipal = nil, nil, resolvePrincipalRealmAware
	auth := func(q *apiTokenLookup, req *pb.AuthReq) (*pb.AuthResp, error) {
		h := &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}, HeaderName: "Authorization", Scheme: "Bearer"}
		return h.Authenticate(context.Background(), req)
	}

	for _, req := range []*pb.AuthReq{
		{Headers: map[string]string{"authorization": "DPoP tok"}},
		{Headers: map[string]string{"authorization": "Bearer tok"}},
		{Headers: map[string]string{"authorization": "Bearer tok", dpopJKTKey: p256JKT}},
	} {
		q := &apiTokenLookup{known: "tok", thumb: p256JKT}
		_, err := auth(q, req)
		wantDeviceRefusal(t, err, CodeDeviceProofRequired)
		if q.lookups != 0 {
			t.Fatalf("the token was looked up before the proof was required")
		}
	}
	_, err := auth(&apiTokenLookup{known: "tok", thumb: p256JKT}, boundAuthReq("tok", ed25519JKT))
	wantOpaque(t, err)
	_, err = auth(&apiTokenLookup{known: "tok"}, boundAuthReq("tok", p256JKT))
	wantOpaque(t, err)

	resp, err := auth(&apiTokenLookup{known: "tok", thumb: p256JKT}, boundAuthReq("tok", p256JKT))
	if err != nil || resp.GetDeviceId() != p256JKT || resp.GetUserId() != "u1" || resp.GetSessionTokenId() != "" {
		t.Fatalf("the bound key's proof: %+v, %v", resp, err)
	}
}

// ── static: device/private-key-never-leaves ─────────────────────────────

// No message of the plugin's API — a request or response of any service,
// a table, an event — has a field that could carry a private key, and the
// public key a request names is never a stored column: only its thumbprint
// is. The heuristics are names; the exceptions are listed with why.
func TestNoAPICarriesAPrivateKey(t *testing.T) {
	privateName := regexp.MustCompile(`^(d|p|q|dp|dq|qi|k|private\w*|\w*_private\w*|priv|priv_\w*|\w*private_key\w*|secret_key|\w*_secret_key|signing_key|key_pair|keypair|jwk)$`)
	exempt := map[string]string{}
	field := regexp.MustCompile(`(?m)^\s*(?:repeated\s+|optional\s+)?[\w.]+\s+(\w+)\s*=\s*\d+`)
	checked := 0
	for _, f := range []string{"business/auth_service.proto", "mutations/auth_mutation.proto", "queries/auth_query.proto", "types/models.proto", "events/auth_events.proto"} {
		raw, err := os.ReadFile("../../proto/" + f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range field.FindAllStringSubmatch(string(raw), -1) {
			checked++
			if privateName.MatchString(m[1]) && exempt[m[1]] == "" {
				t.Errorf("%s: field %q could carry a private key", f, m[1])
			}
		}
	}
	if checked < 300 {
		t.Fatalf("checked %d fields — the scan is not reading the protos", checked)
	}
	// The public key is read by the business handler and dropped: no storage
	// statement takes it, no table holds it.
	for _, f := range []string{"mutations/auth_mutation.proto", "types/models.proto"} {
		raw, err := os.ReadFile("../../proto/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`\bpublic_key\b`).Match(raw) {
			t.Errorf("%s names public_key: a key the request names is kept only as its thumbprint", f)
		}
	}
}

// No log call of the plugin is handed the public key field or a request
// that carries it: what the handlers log is method, outcome and error.
func TestNoLogCallTakesTheKey(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	logCall := regexp.MustCompile(`slog\.\w+\([^\n]*`)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_test.go") || !strings.HasSuffix(f.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range logCall.FindAllString(string(raw), -1) {
			if strings.Contains(call, "PublicKey") || strings.Contains(call, "req)") || strings.Contains(call, `"req"`) {
				t.Errorf("%s: %s", f.Name(), call)
			}
		}
	}
}

// ── round 1 ─────────────────────────────────────────────────────────────

// apiTokenCreatedBy adds to s a person's API token bound to a program's key
// of its own and created from the device approver.
func apiTokenCreatedBy(s *revocationStore, id, userID, approver string) {
	s.addDevice("prog-"+id, userID, "prog-key-"+id).apiKey = true
	s.addToken(id, userID, id+"-bearer", "prog-"+id, pb.TokenType_TOKEN_TYPE_API).approvedBy = approver
}

// A stolen browser session can create an API token bound to the thief's own
// key. Revoking THAT device on purpose — the operator on the admin Devices
// page, or the owner's RevokeDevice — ends the API tokens it created, as it
// ends the CLI sessions it approved; tokens another device created stay.
func TestRevokingOneDevice_EndsTheAPITokensItCreated(t *testing.T) {
	s := devicesAdminStore()
	apiTokenCreatedBy(s, "t-api-d1", "u1", "d1")
	apiTokenCreatedBy(s, "t-api-d2", "u1", "d2")
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}}); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "t-api-d1", "admin", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-api-d2")

	s = devicesAdminStore()
	apiTokenCreatedBy(s, "t-api-d1", "u1", "d1")
	apiTokenCreatedBy(s, "t-api-d2", "u1", "d2")
	h = &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeDevice(ctxOnDevice(t, "u1", "t-other", otherJKT), &pb.RevokeDeviceReq{DeviceId: "d1"}); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "t-api-d1", "u1", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-api-d2")
}

// …while "sign out everywhere (else)" keeps sparing API tokens
// (devices/revoke-all-spares-api-tokens): neither their program keys nor the
// devices that created them end them there.
func TestRevokeOtherAndAllDevices_SpareTheAPITokensTheDevicesCreated(t *testing.T) {
	for name, revoke := range map[string]func(h *AuthServiceHandler, ctx context.Context) error{
		"others": func(h *AuthServiceHandler, ctx context.Context) error {
			_, err := h.RevokeOtherDevices(ctx, &pb.RevokeOtherDevicesReq{})
			return err
		},
		"all": func(h *AuthServiceHandler, ctx context.Context) error {
			_, err := h.RevokeAllDevices(ctx, &pb.RevokeAllDevicesReq{})
			return err
		},
	} {
		s := aliceStore()
		apiTokenCreatedBy(s, "t-api-d1", "u1", "d1")
		h := &AuthServiceHandler{Query: s, Mutation: s}
		if err := revoke(h, ctxOnDevice(t, "u1", "t-other", otherJKT)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.devices["d1"].revokedAt == nil {
			t.Fatalf("%s: the creating device was not revoked — the case is not exercised", name)
		}
		assertLive(t, s, "t-api-d1")
		if s.devices["prog-t-api-d1"].revokedAt != nil {
			t.Errorf("%s: the program's key was revoked", name)
		}
	}
}

// The statement: owner-guarded, by the creating device, the token type the
// handler stamps — never every token of the user.
func TestRevokeApprovedApiTokens_TheStatement(t *testing.T) {
	body := mutationRPCBody(t, "RevokeApprovedApiTokens")
	if !strings.Contains(body, `"WHERE user_id = :user_id AND approved_by_device_id = :device_id AND token_type = :token_type AND revoked_at IS NULL"`) ||
		!strings.Contains(body, `revoke_reason = 5 `) {
		t.Errorf("RevokeApprovedApiTokens is not the guarded update:\n%s", body)
	}
}

// An API token cannot mint a machine token: IssueBotToken needs a signed-in
// session, as CreateApiToken does — the machine account's own token, or an
// operator's API token on a role that may call it, is refused and mints
// nothing.
func TestIssueBotToken_AnAPITokenCallerIsRefused(t *testing.T) {
	withoutOrgs(t)
	s := newKeyStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	raw, err := proto.Marshal(&pb.AuthResp{UserId: "op-1", DeviceId: testJKT})
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, "op-1", "x-w17-scope-tenant_id", "tenant-1", userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
	_, err = h.IssueBotToken(ctx, &pb.IssueBotTokenReq{UserId: "bot-1", PublicKey: p256JWK})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeSessionRequired {
		t.Fatalf("err = %v, want PermissionDenied/%s", err, CodeSessionRequired)
	}
	if len(s.minted) != 0 || len(s.registered) != 0 {
		t.Fatalf("minted %v, registered %v", s.minted, s.registered)
	}
}

// A coordinate spelled with a CR or LF inside decodes to the same key under
// encoding/base64, which skips them, but would hash to another thumbprint
// than the key's: refused, for the request's whole path.
func TestCreateApiToken_RefusesANonCanonicalSpellingOfTheKey(t *testing.T) {
	s := newKeyStore()
	s.put("u1", p256JKT, &pb.Device{})
	h := &AuthServiceHandler{Query: s, Mutation: s}
	jwk := strings.Replace(p256JWK, `"x":"l8tFrhx`, `"x":"l8tF\nrhx`, 1)
	_, err := h.CreateApiToken(operatorCtx("u1", ""), &pb.CreateApiTokenReq{Name: "ci", PublicKey: jwk})
	wantKeyRefusal(t, err, codes.InvalidArgument, CodeDeviceKeyInvalid)
	if len(s.registered) != 0 || len(s.minted) != 0 {
		t.Fatalf("a respelled signed-in key passed as a new program key: registered %v, minted %v", s.registered, s.minted)
	}
}

// ── round 2 ─────────────────────────────────────────────────────────────

// cliSessionCtx is a request from a CLI session (token id sid) of uid, proved
// with the CLI's own key jkt.
func cliSessionCtx(uid, sid, jkt string) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: uid, SessionTokenId: sid, DeviceId: jkt})
	if err != nil {
		panic(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, uid, "x-w17-scope-tenant_id", "tenant-1", userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// The chain: a stolen browser session D approves the thief's CLI key C, and
// the CLI session creates an API token bound to the thief's program key.
// The token records the ROOT approver D, not C — so revoking D (the admin
// Devices page, or the owner's RevokeDevice) ends the CLI session AND the API
// token. Recorded as C, the token would survive D's revocation, and C is
// never revoked by it.
func TestCreateApiToken_FromACLISessionRecordsTheRootApprover(t *testing.T) {
	ks := newKeyStore()
	browser := ks.put("u1", testJKT, &pb.Device{})
	cli := ks.put("u1", otherJKT, &pb.Device{})
	ks.approvers = map[string]string{"t-cli": browser.GetId()}
	h := &AuthServiceHandler{Query: ks, Mutation: ks}
	if _, err := h.CreateApiToken(cliSessionCtx("u1", "t-cli", otherJKT), &pb.CreateApiTokenReq{Name: "thief", PublicKey: ed25519JWK}); err != nil {
		t.Fatal(err)
	}
	minted := ks.minted[0]
	if minted.GetApprovedByDeviceId() != browser.GetId() || minted.GetApprovedByDeviceId() == cli.GetId() {
		t.Fatalf("approver = %q, want the root (browser %s), not the CLI %s", minted.GetApprovedByDeviceId(), browser.GetId(), cli.GetId())
	}
	// The immediate creator stays visible on the event.
	if minted.GetThumbprint() != otherJKT || minted.GetKeyThumbprint() != ed25519JKT || minted.GetCreatedBy() != "u1" {
		t.Errorf("event fields = %q / %q / %q", minted.GetThumbprint(), minted.GetKeyThumbprint(), minted.GetCreatedBy())
	}

	// Revoking the root device D ends the chain, admin and owner alike.
	for name, revoke := range map[string]func(h *AuthServiceHandler) error{
		"admin": func(h *AuthServiceHandler) error {
			_, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}})
			return err
		},
		"owner": func(h *AuthServiceHandler) error {
			_, err := h.RevokeDevice(ctxOnDevice(t, "u1", "t-other", otherJKT), &pb.RevokeDeviceReq{DeviceId: "d1"})
			return err
		},
	} {
		rs := devicesAdminStore()
		cliApprovedBy(rs, "t-cli", "u1", "d1")
		rs.addDevice("prog-thief", "u1", ed25519JKT).apiKey = true
		// The token as CreateApiToken stamped it above: its approver mapped
		// into this store — the browser is "d1" here; any other approver
		// (the CLI's device) maps to none, and the token would survive.
		rs.addToken("t-api-thief", "u1", "thief-bearer", "prog-thief", pb.TokenType_TOKEN_TYPE_API).approvedBy = map[string]string{browser.GetId(): "d1"}[minted.GetApprovedByDeviceId()]
		if err := revoke(&AuthServiceHandler{Query: rs, Mutation: rs}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertRevoked(t, rs, "t-cli", map[string]string{"admin": "admin", "owner": "u1"}[name], pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
		assertRevoked(t, rs, "t-api-thief", map[string]string{"admin": "admin", "owner": "u1"}[name], pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	}
}

// The same root rule for a machine account's token issued from a CLI session.
func TestIssueBotToken_FromACLISessionRecordsTheRootApprover(t *testing.T) {
	withoutOrgs(t)
	ks := newKeyStore()
	laptop := ks.put("op-1", testJKT, &pb.Device{})
	ks.put("op-1", otherJKT, &pb.Device{})
	ks.approvers = map[string]string{"t-cli": laptop.GetId()}
	h := &AuthServiceHandler{Query: ks, Mutation: ks}
	if _, err := h.IssueBotToken(cliSessionCtx("op-1", "t-cli", otherJKT), &pb.IssueBotTokenReq{UserId: "bot-1", PublicKey: p256JWK}); err != nil {
		t.Fatal(err)
	}
	if got := ks.minted[0]; got.GetApprovedByDeviceId() != laptop.GetId() || got.GetCreatedBy() != "op-1" || got.GetUserId() != "bot-1" {
		t.Fatalf("minted %+v, want approved by the operator's root device %s, created by op-1", got, laptop.GetId())
	}
}

// A device its owner already revoked with RevokeOtherDevices — which spares
// API tokens — can still be revoked on the admin Devices page to end the API
// tokens it created; the device's own tokens and row keep their first
// revocation, and no transaction is opened.
func TestRevokeDevices_ARevokedDeviceStillEndsTheAPITokensItCreated(t *testing.T) {
	s := devicesAdminStore()
	apiTokenCreatedBy(s, "t-api-d1", "u1", "d1")
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: s, Mutation: s, DistTx: tx, Connection: "main"}
	if _, err := h.RevokeOtherDevices(ctxOnDevice(t, "u1", "t-other", otherJKT), &pb.RevokeOtherDevicesReq{}); err != nil {
		t.Fatal(err)
	}
	assertLive(t, s, "t-api-d1")
	first := proto.Clone(s.devices["d1"].revokedAt)
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}}); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "t-api-d1", "admin", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	if !proto.Equal(s.devices["d1"].revokedAt, first) || s.tokens["t-session"].revokedBy != "u1" {
		t.Error("the first revocation of the device or its session was rewritten")
	}
	if len(tx.begun) != 0 {
		t.Errorf("a transaction was opened: %v", tx.begun)
	}
}

// ApiTokenCreated: emitted by IssueApiToken with the token, its owner, the
// creating device (device_id, the static rule every device-carrying event
// follows), the program key's thumbprint, the name and the creator — and no
// secret: no token, hash or key member.
func TestApiTokenCreated_TheEvent(t *testing.T) {
	events := readProto(t, "../../proto/events/auth_events.proto")
	msg := regexp.MustCompile(`(?s)message ApiTokenCreated \{(.*?)\n\}`).FindStringSubmatch(events)
	if msg == nil {
		t.Fatal("no ApiTokenCreated event")
	}
	for _, f := range []string{"token_id", "user_id", "device_id", "key_thumbprint", "name", "created_by"} {
		if !regexp.MustCompile(`\bstring\s+` + f + `\s*=`).MatchString(msg[1]) {
			t.Errorf("ApiTokenCreated has no %s", f)
		}
	}
	for _, secret := range []string{"token_hash", "public_key", "jwk", "string token "} {
		if strings.Contains(msg[1], secret) {
			t.Errorf("ApiTokenCreated carries %q", secret)
		}
	}
	body := mutationRPCBody(t, "IssueApiToken")
	for _, want := range []string{`event: "ApiTokenCreated"`, `"$request.key_thumbprint"`, `"$request.created_by"`, `"$response.token.id"`} {
		if !strings.Contains(body, want) {
			t.Errorf("IssueApiToken's emit lacks %s:\n%s", want, body)
		}
	}
	// The values the handler hands the emit.
	ks := newKeyStore()
	h := &AuthServiceHandler{Query: ks, Mutation: ks}
	if _, err := h.CreateApiToken(operatorCtx("u1", testJKT), &pb.CreateApiTokenReq{Name: "ci", PublicKey: p256JWK}); err != nil {
		t.Fatal(err)
	}
	if m := ks.minted[0]; m.GetThumbprint() != testJKT || m.GetKeyThumbprint() != p256JKT || m.GetCreatedBy() != "u1" {
		t.Errorf("emit inputs = %q / %q / %q", m.GetThumbprint(), m.GetKeyThumbprint(), m.GetCreatedBy())
	}
}
