package handlers

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// expiryLookupQuery is a token store holding at most one token, live or
// expired, for both resolvers. A live lookup of an expired token answers
// NotFound, as the generated query does for no row.
type expiryLookupQuery struct {
	pb.AuthQueryClient

	live      *pb.GetTokenWithTypeResp // realm-aware live row; nil = none
	expiredAt *timestamppb.Timestamp   // an expired row; nil = none
	kind      pb.TokenType             // the expired row's kind
	liveErr   error                    // overrides the live lookup's NotFound
	expErr    error                    // the miss-path lookup fails
	expReqs   []*pb.GetExpiredTokenWithTypeReq
	thumb     string // the key the expired token is bound to ("" = testJKT)
	baseReqs  []*pb.GetExpiredTokenReq
}

// boundTo is the key the expired token is bound to: testJKT (the key
// bareAuthenticate proves) unless the test names another.
func (q *expiryLookupQuery) boundTo() string {
	if q.thumb != "" {
		return q.thumb
	}
	return testJKT
}

func (q *expiryLookupQuery) liveMiss() error {
	if q.liveErr != nil {
		return q.liveErr
	}
	return status.Error(codes.NotFound, "no rows")
}

func (q *expiryLookupQuery) GetTokenWithType(context.Context, *pb.GetTokenWithTypeReq, ...grpc.CallOption) (*pb.GetTokenWithTypeResp, error) {
	if q.live == nil {
		return nil, q.liveMiss()
	}
	return q.live, nil
}

func (q *expiryLookupQuery) GetUserByTokenWithPermissions(context.Context, *pb.GetUserByTokenWithPermissionsReq, ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	return nil, q.liveMiss()
}

func (q *expiryLookupQuery) GetExpiredTokenWithType(_ context.Context, in *pb.GetExpiredTokenWithTypeReq, _ ...grpc.CallOption) (*pb.GetExpiredTokenWithTypeResp, error) {
	q.expReqs = append(q.expReqs, in)
	if q.expErr != nil {
		return nil, q.expErr
	}
	if q.expiredAt == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetExpiredTokenWithTypeResp{ExpiresAt: q.expiredAt, TokenType: q.kind, DeviceThumbprint: q.boundTo()}, nil
}

func (q *expiryLookupQuery) GetExpiredToken(_ context.Context, in *pb.GetExpiredTokenReq, _ ...grpc.CallOption) (*pb.GetExpiredTokenResp, error) {
	q.baseReqs = append(q.baseReqs, in)
	if q.expErr != nil {
		return nil, q.expErr
	}
	if q.expiredAt == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetExpiredTokenResp{ExpiresAt: q.expiredAt, DeviceThumbprint: q.boundTo()}, nil
}

func (q *expiryLookupQuery) GetUserRolePermissionsByRealm(context.Context, *pb.GetUserRolePermissionsByRealmReq, ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{}, nil
}

func (q *expiryLookupQuery) GetTokenPermissionSubset(context.Context, *pb.GetTokenPermissionSubsetReq, ...grpc.CallOption) (*pb.GetTokenPermissionSubsetResp, error) {
	return &pb.GetTokenPermissionSubsetResp{}, nil
}

// touchRecorder records the two token writes Authenticate may make. Every
// other mutation is nil and panics if called.
type touchRecorder struct {
	pb.AuthMutationClient
	touches  []*pb.TouchTokenLastUsedReq
	upgrades int
	touchErr error
}

func (r *touchRecorder) TouchTokenLastUsed(_ context.Context, in *pb.TouchTokenLastUsedReq, _ ...grpc.CallOption) (*pb.TouchTokenLastUsedResp, error) {
	r.touches = append(r.touches, in)
	if r.touchErr != nil {
		return nil, r.touchErr
	}
	return &pb.TouchTokenLastUsedResp{}, nil
}

func (r *touchRecorder) UpgradeTokenHash(context.Context, *pb.UpgradeTokenHashReq, ...grpc.CallOption) (*pb.UpgradeTokenHashResp, error) {
	r.upgrades++
	return &pb.UpgradeTokenHashResp{}, nil
}

// bareAuthenticate runs Authenticate with no feature decorators or
// narrowers: what is under test is the token lookup and the touch, and the
// standalone build stages every feature file, whose seams would ask the
// mock for things these tests are not about.
func bareAuthenticate(t *testing.T, h *AuthServiceHandler, token string) (*pb.AuthResp, error) {
	t.Helper()
	prevDec, prevNarrow := scopeDecorators, grantNarrowers
	t.Cleanup(func() { scopeDecorators, grantNarrowers = prevDec, prevNarrow })
	scopeDecorators, grantNarrowers = nil, nil
	h.HeaderName, h.Scheme = "Authorization", "Bearer"
	return h.Authenticate(context.Background(), boundAuthReq(token, testJKT))
}

// errorInfo is google.rpc.ErrorInfo as a client decodes it. Decoded with
// protowire rather than errdetails: these tests also run from the released
// form, which must not need the genproto module the handlers avoid.
type errorInfo struct {
	Reason, Domain string
	Metadata       map[string]string
}

// Nil-safe like generated getters, so a missing detail fails an assertion
// instead of panicking the test binary.
func (e *errorInfo) GetReason() string {
	if e == nil {
		return ""
	}
	return e.Reason
}

func (e *errorInfo) GetDomain() string {
	if e == nil {
		return ""
	}
	return e.Domain
}

func (e *errorInfo) GetMetadata() map[string]string {
	if e == nil {
		return nil
	}
	return e.Metadata
}

// decodeErrorInfo parses google.rpc.ErrorInfo's wire form, failing the test
// on anything a real ErrorInfo decoder would reject or that the encoder
// should not have written.
func decodeErrorInfo(t *testing.T, b []byte) *errorInfo {
	t.Helper()
	out := &errorInfo{Metadata: map[string]string{}}
	strField := func(b []byte) (protowire.Number, string, []byte) {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || typ != protowire.BytesType {
			t.Fatalf("ErrorInfo: bad tag (n=%d, type=%v)", n, typ)
		}
		v, m := protowire.ConsumeBytes(b[n:])
		if m < 0 {
			t.Fatal("ErrorInfo: truncated field")
		}
		return num, string(v), b[n+m:]
	}
	for len(b) > 0 {
		num, v, rest := strField(b)
		b = rest
		switch num {
		case 1:
			out.Reason = v
		case 2:
			out.Domain = v
		case 3:
			var key, val string
			for e := []byte(v); len(e) > 0; {
				n, ev, r := strField(e)
				e = r
				switch n {
				case 1:
					key = ev
				case 2:
					val = ev
				default:
					t.Fatalf("ErrorInfo metadata entry: unexpected field %d", n)
				}
			}
			out.Metadata[key] = val
		default:
			t.Fatalf("ErrorInfo: unexpected field %d", num)
		}
	}
	return out
}

// expiryDetails pulls the two details SESSION_EXPIRED carries off a wire
// status.
func expiryDetails(t *testing.T, err error) (*status.Status, *w17pb.ErrorDetail, *errorInfo) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status error: %v", err)
	}
	var ed *w17pb.ErrorDetail
	var info *errorInfo
	for _, a := range st.Proto().GetDetails() {
		switch {
		case a.MessageIs(&w17pb.ErrorDetail{}):
			ed = &w17pb.ErrorDetail{}
			if err := a.UnmarshalTo(ed); err != nil {
				t.Fatalf("ErrorDetail: %v", err)
			}
		case a.GetTypeUrl() == "type.googleapis.com/google.rpc.ErrorInfo":
			info = decodeErrorInfo(t, a.GetValue())
		default:
			t.Errorf("unexpected detail %s", a.GetTypeUrl())
		}
	}
	return st, ed, info
}

var expiredAt = time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC)

// A session that exists and has expired says so: Unauthenticated, with the
// ErrorDetail a person reads and the ErrorInfo a client dispatches on, both
// SESSION_EXPIRED, the latter carrying the expiry in RFC 3339 UTC.
func TestAuthenticate_ExpiredSessionSaysSo(t *testing.T) {
	// The row's expiry in another zone: the wire must say UTC regardless.
	q := &expiryLookupQuery{expiredAt: timestamppb.New(expiredAt.In(time.FixedZone("CEST", 2*3600))), kind: pb.TokenType_TOKEN_TYPE_SESSION}
	m := &touchRecorder{}
	_, err := bareAuthenticate(t, &AuthServiceHandler{Query: q, Mutation: m}, "expired-tok")

	st, ed, info := expiryDetails(t, err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", st.Code())
	}
	if !strings.Contains(st.Message(), "session expired") {
		t.Errorf("status message = %q, want it to name the expiry", st.Message())
	}
	if ed == nil || ed.GetCode() != CodeSessionExpired {
		t.Fatalf("ErrorDetail = %v, want code %s", ed, CodeSessionExpired)
	}
	if want := "Your session expired on 2026-09-01 08:30 UTC. Sign in again."; ed.GetMessage() != want {
		t.Errorf("ErrorDetail message = %q, want %q", ed.GetMessage(), want)
	}
	if info == nil {
		t.Fatal("no google.rpc.ErrorInfo detail")
	}
	if info.GetReason() != "SESSION_EXPIRED" || info.GetDomain() != "auth.w17" {
		t.Errorf("ErrorInfo = %v, want reason SESSION_EXPIRED domain auth.w17", info)
	}
	if got := info.GetMetadata()["expires_at"]; got != "2026-09-01T08:30:00Z" {
		t.Errorf("ErrorInfo expires_at = %q, want 2026-09-01T08:30:00Z", got)
	}
	// Looked up by the same two keys as the live lookup.
	if len(q.expReqs) != 1 || q.expReqs[0].GetTokenHash() != sha256Hex("expired-tok") || q.expReqs[0].GetLegacyToken() != "expired-tok" {
		t.Errorf("expired lookup = %v, want one, by hash and legacy token", q.expReqs)
	}
	// An expired row is never moved to the hash, nor stamped as used.
	if m.upgrades != 0 || len(m.touches) != 0 {
		t.Errorf("expired token was written to: %d upgrades, %d touches", m.upgrades, len(m.touches))
	}
}

// An expired API token is equally a token that exists and expired; its
// sentence names the remedy that fits it. Same code, same ErrorInfo.
func TestAuthenticate_ExpiredApiTokenSaysSo(t *testing.T) {
	q := &expiryLookupQuery{expiredAt: timestamppb.New(expiredAt), kind: pb.TokenType_TOKEN_TYPE_API}
	_, err := bareAuthenticate(t, &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}}, "api-tok")
	_, ed, info := expiryDetails(t, err)
	if ed.GetCode() != CodeSessionExpired || info.GetReason() != CodeSessionExpired {
		t.Fatalf("details = %v / %v, want SESSION_EXPIRED on both", ed, info)
	}
	if want := "This API token expired on 2026-09-01 08:30 UTC. Create a new token."; ed.GetMessage() != want {
		t.Errorf("message = %q, want %q", ed.GetMessage(), want)
	}
}

// An unknown token — and every case the miss-path lookup cannot vouch for —
// keeps the opaque refusal with NO detail: nothing distinguishes it from any
// other wrong credential.
func TestAuthenticate_UnknownTokenStaysOpaque(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    *expiryLookupQuery
	}{
		{"no such row", &expiryLookupQuery{}},
		{"expired lookup fails", &expiryLookupQuery{expErr: errors.New("boom")}},
		{"expired lookup unavailable", &expiryLookupQuery{expErr: status.Error(codes.Unavailable, "db down")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bareAuthenticate(t, &AuthServiceHandler{Query: tc.q, Mutation: &touchRecorder{}}, "nope")
			st, ed, info := expiryDetails(t, err)
			if st.Code() != codes.Unauthenticated || st.Message() != authnErrorMessage {
				t.Errorf("status = %v %q, want the opaque refusal", st.Code(), st.Message())
			}
			if ed != nil || info != nil || len(st.Details()) != 0 {
				t.Errorf("unknown token carries details %v", st.Details())
			}
		})
	}
}

// An outage on the live lookup stays an outage, and the miss-path lookup is
// not run: it answers only "no row".
func TestAuthenticate_LookupOutageIsNotProbedForExpiry(t *testing.T) {
	q := &expiryLookupQuery{liveErr: status.Error(codes.Unavailable, "db down"), expiredAt: timestamppb.New(expiredAt)}
	_, err := bareAuthenticate(t, &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}}, "tok")
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
	if len(q.expReqs) != 0 {
		t.Errorf("expired lookup ran on an outage: %v", q.expReqs)
	}
}

// The default (api_token off) resolver tells the two apart the same way; with
// one credential class the expired token is a session.
func TestResolvePrincipalSession_ExpiredVsUnknown(t *testing.T) {
	q := &expiryLookupQuery{expiredAt: timestamppb.New(expiredAt)}
	m := &touchRecorder{}
	_, err := resolvePrincipalSession(context.Background(), &AuthServiceHandler{Query: q, Mutation: m}, "s-tok")
	_, ed, info := expiryDetails(t, Unauthenticated(expiredFor(context.Background(), err, testJKT)))
	if ed.GetCode() != CodeSessionExpired || info.GetMetadata()["expires_at"] != "2026-09-01T08:30:00Z" {
		t.Errorf("expired session: details %v / %v", ed, info)
	}
	if !strings.Contains(ed.GetMessage(), "Sign in again") {
		t.Errorf("message = %q, want the session remedy", ed.GetMessage())
	}
	if len(q.baseReqs) != 1 || q.baseReqs[0].GetTokenHash() != sha256Hex("s-tok") || q.baseReqs[0].GetLegacyToken() != "s-tok" {
		t.Errorf("expired lookup = %v, want one, by hash and legacy token", q.baseReqs)
	}
	if m.upgrades != 0 {
		t.Errorf("expired legacy row was moved to the hash")
	}

	q = &expiryLookupQuery{}
	_, err = resolvePrincipalSession(context.Background(), &AuthServiceHandler{Query: q, Mutation: m}, "s-tok")
	if st, _ := status.FromError(Unauthenticated(err)); len(st.Details()) != 0 || st.Code() != codes.Unauthenticated {
		t.Errorf("unknown token: %v %v, want the opaque refusal", st.Code(), st.Details())
	}
}

func liveToken(lastUsed *timestamppb.Timestamp) *pb.GetTokenWithTypeResp {
	return &pb.GetTokenWithTypeResp{
		StoredTokenHash: "stored", UserId: "u1", TokenId: "tok-1",
		TokenType: pb.TokenType_TOKEN_TYPE_API, User: &pb.User{Id: "u1"},
		LastUsedAt: lastUsed, DeviceThumbprint: testJKT,
	}
}

// last_used_at is written on a successful authentication, at most once per
// window: a token never recorded, or recorded before the window, is touched
// once with a cutoff of NOW minus the window (the SQL guard for concurrent
// requests); one recorded within the window costs no statement at all.
func TestAuthenticate_TouchesLastUsedAtThrottled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lastUsed *timestamppb.Timestamp
		want     int
	}{
		{"never recorded", nil, 1},
		{"recorded before the window", timestamppb.New(time.Now().Add(-2 * time.Minute)), 1},
		{"recorded within the window", timestamppb.New(time.Now().Add(-10 * time.Second)), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &touchRecorder{}
			before := time.Now()
			if _, err := bareAuthenticate(t, &AuthServiceHandler{Query: &expiryLookupQuery{live: liveToken(tc.lastUsed)}, Mutation: m}, "tok"); err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if len(m.touches) != tc.want {
				t.Fatalf("touches = %d, want %d", len(m.touches), tc.want)
			}
			if tc.want == 0 {
				return
			}
			got := m.touches[0]
			if got.GetTokenId() != "tok-1" {
				t.Errorf("touched %q, want the resolved row tok-1 (an API token's id too)", got.GetTokenId())
			}
			// One clock: the cutoff is exactly the stamp minus the window.
			if d := got.GetUsedAt().AsTime().Sub(got.GetCutoff().AsTime()); d != tokenUseWindow {
				t.Errorf("used_at - cutoff = %v, want exactly %v", d, tokenUseWindow)
			}
			cutoff := got.GetCutoff().AsTime()
			if d := before.Sub(cutoff); d < tokenUseWindow-time.Second || d > tokenUseWindow+5*time.Second {
				t.Errorf("cutoff is %v before now, want ~%v", d, tokenUseWindow)
			}
		})
	}
}

// A failed last_used_at write never fails the authentication it rides on.
func TestAuthenticate_FailedTouchDoesNotFailAuth(t *testing.T) {
	m := &touchRecorder{touchErr: status.Error(codes.Unavailable, "db down")}
	resp, err := bareAuthenticate(t, &AuthServiceHandler{Query: &expiryLookupQuery{live: liveToken(nil)}, Mutation: m}, "tok")
	if err != nil || resp.GetUserId() != "u1" {
		t.Fatalf("authenticate = %v, %v; want success despite the failed touch", resp, err)
	}
	if len(m.touches) != 1 {
		t.Errorf("touches = %d, want the one attempted write", len(m.touches))
	}
}

// A refused authentication records no use.
func TestAuthenticate_RefusedTokenIsNotTouched(t *testing.T) {
	tok := liveToken(nil)
	tok.User.DisabledAt = timestamppb.Now()
	m := &touchRecorder{}
	if _, err := bareAuthenticate(t, &AuthServiceHandler{Query: &expiryLookupQuery{live: tok}, Mutation: m}, "tok"); err == nil {
		t.Fatal("a disabled account authenticated")
	}
	if len(m.touches) != 0 {
		t.Errorf("refused token was touched: %v", m.touches)
	}
}

// The statements behind the three behaviours, held to the shape that makes
// them safe. A fake store cannot run SQL, so this pins the text; the live
// proof is a generated project's migration + query compile.
func TestSessionExpiryStatements(t *testing.T) {
	queries := readProto(t, filepath.Join("..", "..", "proto", "queries", "auth_query.proto"))
	mutations := readProto(t, filepath.Join("..", "..", "proto", "mutations", "auth_mutation.proto"))

	// The miss-path lookups find EXPIRED rows only, by the live lookup's keys.
	for _, rpc := range []string{"rpc GetExpiredToken(", "rpc GetExpiredTokenWithType("} {
		dql := methodDQL(t, queries, rpc)
		for _, want := range []string{
			"(t.token_hash = :token_hash OR t.token = :legacy_token) AND t.expires_at <= NOW()",
			"t.expires_at AS expires_at",
		} {
			if !strings.Contains(dql, want) {
				t.Errorf("%s lacks %q:\n%s", rpc, want, dql)
			}
		}
	}
	// The live lookup reads last_used_at, for the handler's pre-check.
	if dql := methodDQL(t, queries, "rpc GetTokenWithType("); !strings.Contains(dql, "t.last_used_at AS last_used_at") {
		t.Errorf("GetTokenWithType does not project last_used_at:\n%s", dql)
	}

	// The touch is throttled IN the statement, so concurrent requests that all
	// passed the handler's pre-check still write once.
	touch := methodDQL(t, mutations, "rpc TouchTokenLastUsed(")
	if !strings.Contains(touch, "SET last_used_at = :used_at ") ||
		!strings.Contains(touch, "WHERE id = :token_id AND (last_used_at IS NULL OR last_used_at < :cutoff)") {
		t.Errorf("TouchTokenLastUsed is not throttled in SQL:\n%s", touch)
	}

	// The sweep: one user's expired SESSION tokens, in the mint's own
	// transaction, before the insert.
	issue := methodDQL(t, mutations, "rpc IssueToken(")
	sweep := strings.Index(issue, `name: "sweep"`)
	main := strings.Index(issue, `name: "main"`)
	if sweep < 0 || main < 0 || sweep > main {
		t.Fatalf("IssueToken has no sweep op ahead of the insert:\n%s", issue)
	}
	sweepDQL := issue[sweep:main]
	for _, want := range []string{
		"DELETE FROM @module.UserToken ",
		// Only this user's rows.
		"WHERE user_id = :user_id ",
		// Only expired ones: a NULL (never-expiring) row does not match.
		"AND expires_at <= NOW() ",
		// Never an API or bot token. A top-level AND operand of a mutation's
		// WHERE, the one place a SELECT-less gate may sit.
		"AND ?feature(api_token) token_type = 1",
	} {
		if !strings.Contains(sweepDQL, want) {
			t.Errorf("IssueToken sweep lacks %q:\n%s", want, sweepDQL)
		}
	}
	// An OR anywhere would let a row escape one of the conjuncts above.
	if strings.Contains(sweepDQL, " OR ") {
		t.Errorf("IssueToken sweep has an OR; every guard must be a conjunct:\n%s", sweepDQL)
	}
}

// The wire states the expiry in UTC whatever zone the time arrives in — the
// metadata is RFC 3339 for a machine and the sentence says "UTC".
func TestSessionExpired_StatesUTC(t *testing.T) {
	_, ed, info := expiryDetails(t, sessionExpired(context.Background(), expiredAt.In(time.FixedZone("X", -5*3600)), pb.TokenType_TOKEN_TYPE_SESSION))
	if got := info.GetMetadata()["expires_at"]; got != "2026-09-01T08:30:00Z" {
		t.Errorf("expires_at = %q, want 2026-09-01T08:30:00Z", got)
	}
	if !strings.Contains(ed.GetMessage(), "2026-09-01 08:30 UTC") {
		t.Errorf("message = %q, want the UTC time", ed.GetMessage())
	}
}

// The hand-encoded ErrorInfo round-trips every field, several metadata
// entries included, and encodes the same bytes every time.
func TestErrorInfoAny_WireForm(t *testing.T) {
	md := map[string]string{"expires_at": "2026-09-01T08:30:00Z", "b": "2", "a": ""}
	a := errorInfoAny("R", "d.example", md)
	if a.GetTypeUrl() != "type.googleapis.com/google.rpc.ErrorInfo" {
		t.Errorf("type url = %q", a.GetTypeUrl())
	}
	got := decodeErrorInfo(t, a.GetValue())
	if got.Reason != "R" || got.Domain != "d.example" || len(got.Metadata) != 3 {
		t.Fatalf("decoded %+v", got)
	}
	for k, v := range md {
		if got.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, got.Metadata[k], v)
		}
	}
	for i := 0; i < 20; i++ {
		if string(errorInfoAny("R", "d.example", md).GetValue()) != string(a.GetValue()) {
			t.Fatal("encoding is not deterministic")
		}
	}
}
