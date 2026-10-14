package handlers

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The admin Devices page (user_admin): every device of every account, and the
// operator's Revoke, which ends the device and every token bound to it
// (device/revoke-device-ends-everything, the plugin's side).

// GetDevice is the Devices detail read the Revoke action reads first: the
// row's account and whether it is already revoked (id AND nothing else — the
// page spans every account).
func (s *revocationStore) GetDevice(_ context.Context, in *pb.GetDeviceReq, _ ...grpc.CallOption) (*pb.DeviceAdminRow, error) {
	d := s.devices[in.GetId()]
	if d == nil {
		return nil, notFound()
	}
	row := &pb.DeviceAdminRow{Id: d.id, User: d.userID, Thumbprint: d.thumb, Label: d.label, Ip: d.ip, RevokedAt: d.revokedAt}
	if u := s.users[d.userID]; u != nil {
		row.Owner = u.email
	}
	return row, nil
}

// devicesAdminStore: alice (u1) with two devices and an API token on the
// first; bob (u2) using the SAME key as alice's first device — a second
// (user, device) pair — with a session of his own.
func devicesAdminStore() *revocationStore {
	s := aliceStore()
	s.addUser("admin", "ops@example.com")
	s.addUser("u2", "bob@example.com")
	s.addDevice("d3", "u2", testJKT)
	s.addToken("t-bob", "u2", "bob-session", "d3", pb.TokenType_TOKEN_TYPE_SESSION)
	return s
}

func adminCtx() context.Context { return sessionCallerCtx("admin", "t-admin") }

// The operator revokes alice's first device: the device is revoked for good,
// every token bound to it — the session and the API token — is revoked with
// reason DEVICE_REVOKED and the OPERATOR as the actor, and the rows stay. The
// key's holder then hears DEVICE_REVOKED; anyone else the opaque refusal, as
// for an expired token. Alice's other device, and bob's pair on the same key,
// are untouched: revocation belongs to the (user, device) pair.
func TestRevokeDevices_RevokesTheDeviceAndEveryTokenOnIt(t *testing.T) {
	s := devicesAdminStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if s.devices["d1"].revokedAt == nil {
		t.Fatal("the device is not revoked")
	}
	session := assertRevoked(t, s, "t-session", "admin", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertRevoked(t, s, "t-api", "admin", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-other")
	assertLive(t, s, "t-bob")
	if s.devices["d2"].revokedAt != nil || s.devices["d3"].revokedAt != nil {
		t.Error("another device was revoked with it")
	}
	assertRefusedLikeExpired(t, s, h, session, "alice-session")
	err := authenticateWith(t, h, resolvePrincipalRealmAware, "alice-session", testJKT)
	if d := detailOf(t, err); d.GetCode() != CodeDeviceRevoked {
		t.Errorf("the key's holder was told %v, want %s", d, CodeDeviceRevoked)
	}
	if err := authenticateWith(t, h, resolvePrincipalRealmAware, "bob-session", testJKT); err != nil {
		t.Errorf("bob's pair on the same key stopped working: %v", err)
	}
}

// A device already revoked is left as it is: its first revocation — time,
// actor, reason — stands, and no transaction is even opened for it. Unknown
// ids are done, not an error; an empty selection (the admin's "all rows") is
// refused before anything is read.
func TestRevokeDevices_ARevokedDeviceIsANoOp(t *testing.T) {
	s := devicesAdminStore()
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: s, Mutation: s, DistTx: tx, Connection: "main"}
	// alice revokes it herself first.
	if _, err := h.RevokeDevice(sessionCallerCtx("u1", "t-other"), &pb.RevokeDeviceReq{DeviceId: "d1"}); err != nil {
		t.Fatalf("self revoke: %v", err)
	}
	first := proto.Clone(s.devices["d1"].revokedAt)
	firstTok := *s.tokens["t-session"]

	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1", "no-such-device"}}); err != nil {
		t.Fatalf("revoking a revoked device answered an error: %v", err)
	}
	if !proto.Equal(s.devices["d1"].revokedAt, first) {
		t.Error("the device's revocation was rewritten")
	}
	tok := s.tokens["t-session"]
	if tok.revokedBy != "u1" || !proto.Equal(tok.revokedAt, firstTok.revokedAt) {
		t.Errorf("the token's first revocation was rewritten: by %q at %v", tok.revokedBy, tok.revokedAt)
	}
	if len(tx.begun) != 0 {
		t.Errorf("a transaction was opened for nothing to do: %v", tx.begun)
	}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an empty selection answered %v, want InvalidArgument", err)
	}
	if _, err := h.RevokeDevices(context.Background(), &pb.RevokeDevicesReq{Ids: []string{"d2"}}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no operator answered %v, want Unauthenticated", err)
	}
	assertLive(t, s, "t-other")
}

// A LEGACY device (no key: recorded before device binding) can never be used,
// and revoking one is allowed all the same: it records the operator's decision
// and ends whatever token still names it.
func TestRevokeDevices_ALegacyDeviceIsRevokedLikeAnyOther(t *testing.T) {
	s := devicesAdminStore()
	s.addDevice("d-legacy", "u1", "")
	s.addToken("t-legacy", "u1", "alice-legacy", "d-legacy", pb.TokenType_TOKEN_TYPE_SESSION)
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d-legacy"}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if s.devices["d-legacy"].revokedAt == nil {
		t.Error("the legacy device is not revoked")
	}
	assertRevoked(t, s, "t-legacy", "admin", pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED)
	assertLive(t, s, "t-session")
}

// txLog records the transaction each revoking statement ran in.
type txLog struct {
	*revocationStore
	calls   []string
	failArm string
}

func (l *txLog) RevokeDeviceTokens(ctx context.Context, in *pb.RevokeDeviceTokensReq, o ...grpc.CallOption) (*pb.RevokeDeviceTokensResp, error) {
	l.calls = append(l.calls, "tokens@"+outgoingTxID(ctx))
	if l.failArm == "tokens" {
		return nil, status.Error(codes.Unavailable, "db down")
	}
	return l.revocationStore.RevokeDeviceTokens(ctx, in, o...)
}

func (l *txLog) MarkDeviceRevoked(ctx context.Context, in *pb.MarkDeviceRevokedReq, o ...grpc.CallOption) (*pb.MarkDeviceRevokedResp, error) {
	l.calls = append(l.calls, "device@"+outgoingTxID(ctx))
	if l.failArm == "device" {
		return nil, status.Error(codes.Unavailable, "db down")
	}
	return l.revocationStore.MarkDeviceRevoked(ctx, in, o...)
}

// The device and its tokens end together: both statements run in ONE
// transaction per device, committed; a failure of either rolls the device's
// revocation back and is reported.
func TestRevokeDevices_OneTransactionPerDevice(t *testing.T) {
	l := &txLog{revocationStore: devicesAdminStore()}
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: l, Mutation: l, DistTx: tx, Connection: "main"}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1", "d2"}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	want := "tokens@" + fakeTxID + " device@" + fakeTxID
	if got := strings.Join(l.calls, " "); got != want+" "+want {
		t.Errorf("statements = %s, want each device's pair in a transaction", got)
	}
	if len(tx.begun) != 2 || len(tx.committed) != 2 || len(tx.rolledBack) != 0 {
		t.Errorf("transactions: begun %v committed %v rolled back %v, want two committed", tx.begun, tx.committed, tx.rolledBack)
	}
	for _, arm := range []string{"tokens", "device"} {
		l := &txLog{revocationStore: devicesAdminStore(), failArm: arm}
		tx := &recordingDistTx{}
		h := &AuthServiceHandler{Query: l, Mutation: l, DistTx: tx, Connection: "main"}
		if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}}); status.Code(err) != codes.Unavailable {
			t.Errorf("%s failing: err = %v, want the outage", arm, err)
		}
		if len(tx.committed) != 0 || len(tx.rolledBack) != 1 {
			t.Errorf("%s failing: committed %v rolled back %v, want one rollback", arm, tx.committed, tx.rolledBack)
		}
	}
}

// A device read that does not answer refuses the action instead of revoking
// blind (and a NotFound is the unknown id above, done).
func TestRevokeDevices_AFailedReadRefuses(t *testing.T) {
	s := devicesAdminStore()
	h := &AuthServiceHandler{Query: failingDeviceRead{s}, Mutation: s}
	if _, err := h.RevokeDevices(adminCtx(), &pb.RevokeDevicesReq{Ids: []string{"d1"}}); status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v, want the outage", err)
	}
	assertLive(t, s, "t-session")
}

type failingDeviceRead struct{ *revocationStore }

func (failingDeviceRead) GetDevice(context.Context, *pb.GetDeviceReq, ...grpc.CallOption) (*pb.DeviceAdminRow, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}

// ── the statements ────────────────────────────────────────────

// The Devices page lists EVERY device — revoked and legacy ones included, so
// no WHERE at all — the most recently seen first, with the owner's address and
// the trust the sign-in would grant: trusted_at later than the account's
// revocation, and the device not revoked. The detail reads the same
// projection for one row.
func TestDevicesAdminStatements(t *testing.T) {
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	list, get := q["ListAllDevices"], q["GetDevice"]
	for _, want := range []string{
		`FROM @module.Device d `,
		`LEFT JOIN @module.User u ON u.id = d.user_id `,
		`COALESCE(u.email, '') AS owner`,
		`d.thumbprint AS thumbprint`,
		`d.created_at AS created_at, d.last_seen_at AS last_seen_at`,
		`d.trusted_at AS trusted_at, u.device_trust_revoked_at AS trust_revoked_at`,
		`CASE WHEN d.trusted_at IS NOT NULL AND d.revoked_at IS NULL `,
		`AND (u.device_trust_revoked_at IS NULL OR d.trusted_at > u.device_trust_revoked_at) `,
		`THEN TRUE ELSE FALSE END AS trusted`,
		`d.revoked_at AS revoked_at`,
	} {
		if !strings.Contains(list, want) || !strings.Contains(get, want) {
			t.Errorf("ListAllDevices / GetDevice lack %q:\n%s\n%s", want, list, get)
		}
	}
	if !strings.Contains(list, `ORDER BY d.last_seen_at DESC, d.id DESC`) || strings.Contains(list, "WHERE") {
		t.Errorf("ListAllDevices is not every device, the most recently seen first:\n%s", list)
	}
	if !strings.Contains(get, `WHERE d.id = :id`) {
		t.Errorf("GetDevice does not read the one row:\n%s", get)
	}
	for name, body := range map[string]string{"ListAllDevices": list, "GetDevice": get} {
		if !strings.Contains(body, `plugin_feature_rpc) = "user_admin`) {
			t.Errorf("%s is not gated user_admin", name)
		}
	}
	// The revoke primitives are base tier: the devices calls and the admin
	// page both compose them, and an rpc carries one gate.
	src := dqlText(authProtos(t)["mutations/auth_mutation.proto"])
	m := rpcBodies(src)
	for _, name := range []string{"RevokeDeviceTokens", "MarkDeviceRevoked"} {
		if strings.Contains(m[name], "plugin_feature_rpc") {
			t.Errorf("%s is feature-gated; user_admin and devices both need it:\n%s", name, m[name])
		}
		for _, msg := range []string{name + "Req", name + "Resp"} {
			i := strings.Index(src, "message "+msg+" {")
			if i < 0 {
				t.Fatalf("no message %s", msg)
			}
			if block := src[i : i+strings.Index(src[i:], "}")]; strings.Contains(block, "plugin_feature") {
				t.Errorf("message %s is feature-gated:\n%s", msg, block)
			}
		}
	}
	if !strings.Contains(m["RevokeDeviceTokens"], "revoked_by = :revoked_by, revoke_reason = 5 ") ||
		!strings.Contains(m["RevokeDeviceTokens"], "WHERE user_id = :user_id AND device_id = :device_id AND revoked_at IS NULL") {
		t.Errorf("RevokeDeviceTokens does not record the actor it is given:\n%s", m["RevokeDeviceTokens"])
	}
}

// The Sessions page shows each token's device — its row (linked to the Devices
// page), label and key — whether it is a public-computer session, and on the
// detail the device that approved a CLI session; never the secret.
func TestSessionsAdminStatements_ShowTheDevice(t *testing.T) {
	q := rpcBodies(dqlText(authProtos(t)["queries/auth_query.proto"]))
	list, get := q["ListUserTokens"], q["GetUserToken"]
	for _, want := range []string{
		`t.device_id AS device, COALESCE(d.label, '') AS device_label`,
		`d.thumbprint AS thumbprint, t.public_computer AS public_computer`,
		`LEFT JOIN @module.Device d ON d.id = t.device_id `,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("ListUserTokens lacks %q:\n%s", want, list)
		}
	}
	for _, want := range []string{
		`returns (UserTokenAdminDetail)`,
		`t.public_computer AS public_computer`,
		`t.device_id AS device_id, COALESCE(d.label, '') AS device_label`,
		`d.thumbprint AS device_thumbprint`,
		`t.approved_by_device_id AS approved_by_device_id`,
		`COALESCE(a.label, '') AS approver_label, a.thumbprint AS approver_thumbprint`,
		`LEFT JOIN @module.Device d ON d.id = t.device_id `,
		`LEFT JOIN @module.Device a ON a.id = t.approved_by_device_id `,
	} {
		if !strings.Contains(get, want) {
			t.Errorf("GetUserToken lacks %q:\n%s", want, get)
		}
	}
	for name, body := range map[string]string{"ListUserTokens": list, "GetUserToken": get} {
		if regexp.MustCompile(`t\.token\b|token_hash`).MatchString(body) {
			t.Errorf("%s projects the secret:\n%s", name, body)
		}
	}
	// The detail DTO carries nothing secret either.
	fields := (&pb.UserTokenAdminDetail{}).ProtoReflect().Descriptor().Fields()
	for _, secret := range []protoreflect.Name{"token", "token_hash"} {
		if fields.ByName(secret) != nil {
			t.Errorf("UserTokenAdminDetail has a %s field", secret)
		}
	}
}

// ── the admin pages ───────────────────────────────────────────

// pageBlock is one admin page of plugin.yaml's preset, up to the next page.
func pageBlock(t *testing.T, manifest, name string) string {
	t.Helper()
	i := strings.Index(manifest, "      - name: "+name+"\n")
	if i < 0 {
		t.Fatalf("no %s page", name)
	}
	block := manifest[i+1:]
	if end := strings.Index(block, "\n      - name: "); end > 0 {
		block = block[:end]
	}
	if end := strings.Index(block, "\n\n"); end > 0 {
		block = block[:end]
	}
	return block
}

// listColumns are the field names a page's list.columns names, in order.
func listColumns(block string) []string {
	i := strings.Index(block, "columns:")
	j := strings.Index(block, "detail_link_column:")
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^\s+- (?:\{ name: )?(\w+)`).FindAllStringSubmatch(block[i:j], -1) {
		out = append(out, m[1])
	}
	return out
}

func readonlyFields(block string) []string {
	m := regexp.MustCompile(`readonly_fields: \[([^\]]*)\]`).FindStringSubmatch(block)
	if m == nil {
		return nil
	}
	return strings.Split(strings.ReplaceAll(m[1], " ", ""), ",")
}

func assertFieldsExist(t *testing.T, what string, msg proto.Message, names []string) {
	t.Helper()
	fields := msg.ProtoReflect().Descriptor().Fields()
	for _, n := range names {
		if fields.ByName(protoreflect.Name(n)) == nil {
			t.Errorf("%s names %q, which %s does not have", what, n, msg.ProtoReflect().Descriptor().Name())
		}
	}
}

// The Devices page: user_admin, listed by ListAllDevices and read by
// GetDevice, revoked through the service method that records the operator and
// ends the tokens, never deleted. Every column and detail field exists on the
// projection, and the Sessions page links its device column to it.
func TestAdminPages_DevicesAndTheSessionsDeviceColumn(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	devices := pageBlock(t, manifest, "Devices")
	for _, want := range []string{
		"model: Device\n", "feature: user_admin\n", "source: AuthQuery.ListAllDevices\n",
		"read: AuthQuery.GetDevice\n", "source: AuthService.RevokeDevices\n", "detail_link_column: owner\n",
		"{ name: user, ref: { page: Users } }",
	} {
		if !strings.Contains(devices, want) {
			t.Errorf("the Devices page lacks %q:\n%s", want, devices)
		}
	}
	if strings.Contains(devices, "delete:") || strings.Contains(devices, "update:") {
		t.Errorf("the Devices page deletes or edits:\n%s", devices)
	}
	cols := listColumns(devices)
	if strings.Join(cols, ",") != "owner,user,label,thumbprint,ip,created_at,last_seen_at,trusted,revoked_at" {
		t.Errorf("Devices columns = %v", cols)
	}
	assertFieldsExist(t, "Devices list", &pb.DeviceAdminRow{}, cols)
	assertFieldsExist(t, "Devices detail", &pb.DeviceAdminRow{}, readonlyFields(devices))

	sessions := pageBlock(t, manifest, "Sessions")
	if !strings.Contains(sessions, "{ name: device, ref: { title: device_label, page: Devices } }") {
		t.Errorf("the Sessions page does not link the device to the Devices page:\n%s", sessions)
	}
	scols := listColumns(sessions)
	for _, c := range []string{"device", "thumbprint", "public_computer", "revoked_at", "revoke_reason"} {
		if !strings.Contains(","+strings.Join(scols, ",")+",", ","+c+",") {
			t.Errorf("Sessions columns %v lack %s", scols, c)
		}
	}
	assertFieldsExist(t, "Sessions list", &pb.UserTokenAdminRow{}, append(scols, "device_label"))
	sro := readonlyFields(sessions)
	assertFieldsExist(t, "Sessions detail", &pb.UserTokenAdminDetail{}, sro)
	for _, c := range []string{"device_id", "device_label", "device_thumbprint", "approved_by_device_id", "approver_label", "approver_thumbprint", "public_computer"} {
		if !strings.Contains(","+strings.Join(sro, ",")+",", ","+c+",") {
			t.Errorf("the Sessions detail does not show %s: %v", c, sro)
		}
	}
	signIns := pageBlock(t, manifest, "SignIns")
	assertFieldsExist(t, "SignIns detail", &pb.SignInEvent{}, readonlyFields(signIns))
	if !strings.Contains(signIns, "public_computer") {
		t.Errorf("the SignIns detail does not show public_computer:\n%s", signIns)
	}
}
