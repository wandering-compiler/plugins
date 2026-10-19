package handlers

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// bot_token_guard: a machine account's address allowlist and use summary.

func (r *touchRecorder) RecordBotTokenUse(_ context.Context, in *pb.RecordBotTokenUseReq, _ ...grpc.CallOption) (*pb.RecordBotTokenUseResp, error) {
	r.botUses = append(r.botUses, in)
	return &pb.RecordBotTokenUseResp{}, nil
}

// guardReq is a bearer request as the gateway hands it on: the client address
// it resolved, the surface and the method.
func guardReq(token, addr string) *pb.AuthReq {
	req := bearerReq(token)
	req.Headers[clientAddrKey] = addr
	req.Headers[surfaceKey] = "rpc"
	req.Headers[methodKey] = "/pkg.Svc/Fetch"
	return req
}

func resetBotUseSeen(t *testing.T) {
	t.Helper()
	botUseMu.Lock()
	botUseSeen = map[string]time.Time{}
	botUseMu.Unlock()
}

// With an allowlist, a bearer token passes only from an address inside it —
// the address the gateway resolved, an IPv4-mapped IPv6 one read as IPv4 —
// and is refused, opaquely and unrecorded, from anywhere else and when the
// gateway resolved none. Without a list it passes from anywhere.
func TestAuthenticate_ABotBearerTokenIsHeldToItsAllowlist(t *testing.T) {
	resetBotUseSeen(t)
	q := aBotBearer(botTok)
	q.cidrs = "203.0.113.0/24,2001:db8::/32"
	for _, addr := range []string{"203.0.113.7", "::ffff:203.0.113.8", "2001:db8::1"} {
		if _, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, addr)); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"198.51.100.1", "", "not-an-address", "2001:db9::1"} {
		_, rec, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, addr))
		wantOpaque(t, err)
		if len(rec.touches) != 0 || len(rec.botUses) != 0 {
			t.Errorf("%q: a refused request was recorded as used", addr)
		}
	}
	q.cidrs = ""
	if _, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, "198.51.100.1")); err != nil {
		t.Errorf("no allowlist: %v", err)
	}
	// A stored list that no longer parses does not widen to anywhere.
	q.cidrs = "garbage"
	_, _, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, "203.0.113.7"))
	wantOpaque(t, err)
}

// An accepted bearer request lands in the use summary with its address,
// surface and method, written once a minute per combination.
func TestAuthenticate_ABotBearerUseIsSummarised(t *testing.T) {
	resetBotUseSeen(t)
	q := aBotBearer(botTok)
	_, rec, err := bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, "::ffff:203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.botUses) != 1 {
		t.Fatalf("uses = %d, want 1", len(rec.botUses))
	}
	u := rec.botUses[0]
	if u.GetTokenId() != "tok-b" || u.GetUserId() != "bot-1" || u.GetAddress() != "203.0.113.7" || u.GetSurface() != "rpc" || u.GetMethod() != "/pkg.Svc/Fetch" || u.GetUsedAt() == nil {
		t.Errorf("use = %+v", u)
	}
	_, rec, _ = bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, "203.0.113.7"))
	if len(rec.botUses) != 0 {
		t.Error("the same combination was written twice within a minute")
	}
	_, rec, _ = bearerAuthenticate(t, resolvePrincipalRealmAware, q, guardReq(botTok, "203.0.113.9"))
	if len(rec.botUses) != 1 {
		t.Error("a new address was not written")
	}
}

// An allowlist entry is a CIDR or an address; it is stored masked, an address
// as its /32 or /128, duplicates dropped. Anything else, and more than the
// cap, is refused on the field.
func TestCanonicalAllowlist(t *testing.T) {
	got, err := canonicalAllowlist(context.Background(), []string{" 203.0.113.7 ", "203.0.113.9/24", "203.0.113.0/24", "", "2001:db8::1", "::ffff:198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "203.0.113.7/32,203.0.113.0/24,2001:db8::1/128,198.51.100.1/32" {
		t.Errorf("canonical = %v", got)
	}
	for _, bad := range [][]string{{"example.com"}, {"203.0.113.0/33"}} {
		_, err := canonicalAllowlist(context.Background(), bad)
		if status.Code(err) != codes.InvalidArgument || detailOf(t, err).GetCode() != CodeBotAllowlistInvalid || detailOf(t, err).GetField() != "cidrs" {
			t.Errorf("%v: %v", bad, err)
		}
	}
	many := make([]string, maxAllowlistEntries+1)
	for i := range many {
		many[i] = "10.0.0." + strconv.Itoa(i)
	}
	if _, err := canonicalAllowlist(context.Background(), many); detailOf(t, err).GetCode() != CodeBotAllowlistInvalid {
		t.Errorf("too many: %v", err)
	}
}

// guardStore is the key store with the bot_token_guard statements.
type guardStore struct {
	*keyStore
	cidrs string
	sets  []*pb.SetBotAllowedCidrsReq
	uses  []*pb.BotTokenUseRow
}

func (s *guardStore) SetBotAllowedCidrs(_ context.Context, in *pb.SetBotAllowedCidrsReq, _ ...grpc.CallOption) (*pb.SetBotAllowedCidrsResp, error) {
	s.sets = append(s.sets, in)
	s.cidrs = in.GetAllowedCidrs()
	return &pb.SetBotAllowedCidrsResp{Id: in.GetUserId()}, nil
}

func (s *guardStore) GetBotAllowedCidrs(context.Context, *pb.GetBotAllowedCidrsReq, ...grpc.CallOption) (*pb.GetBotAllowedCidrsResp, error) {
	return &pb.GetBotAllowedCidrsResp{AllowedCidrs: s.cidrs}, nil
}

func (s *guardStore) ListBotTokenUses(context.Context, *pb.ListBotTokenUsesReq, ...grpc.CallOption) (*pb.ListBotTokenUsesResp, error) {
	if len(s.uses) == 0 {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.ListBotTokenUsesResp{Rows: s.uses}, nil
}

// An operator sets a bot's allowlist and reads it back canonical, with the
// use summary; a person, an unknown account and an API-token caller are
// refused and nothing is written.
func TestSetBotAllowlistAndGetBotGuard(t *testing.T) {
	withoutOrgs(t)
	s := &guardStore{keyStore: newKeyStore()}
	h := &AuthServiceHandler{Query: s, Mutation: s}
	op := operatorCtx("op-1", testJKT)

	resp, err := h.SetBotAllowlist(op, &pb.SetBotAllowlistReq{UserId: "bot-1", Cidrs: []string{"203.0.113.7", "198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(resp.GetCidrs(), ",") != "203.0.113.7/32,198.51.100.0/24" || len(s.sets) != 1 || s.sets[0].GetUserId() != "bot-1" || s.cidrs != "203.0.113.7/32,198.51.100.0/24" {
		t.Fatalf("resp %v, stored %q (%d writes)", resp.GetCidrs(), s.cidrs, len(s.sets))
	}
	g, err := h.GetBotGuard(op, &pb.GetBotGuardReq{UserId: "bot-1"})
	if err != nil || strings.Join(g.GetCidrs(), ",") != s.cidrs || len(g.GetUses()) != 0 {
		t.Fatalf("guard = %+v, %v", g, err)
	}
	s.uses = []*pb.BotTokenUseRow{{TokenId: "tok-b", Address: "203.0.113.7", Surface: "rpc", Method: "/pkg.Svc/Fetch"}}
	if g, err = h.GetBotGuard(op, &pb.GetBotGuardReq{UserId: "bot-1"}); err != nil || len(g.GetUses()) != 1 || g.GetUses()[0].GetMethod() != "/pkg.Svc/Fetch" {
		t.Fatalf("guard = %+v, %v", g, err)
	}
	if _, err := h.SetBotAllowlist(op, &pb.SetBotAllowlistReq{UserId: "bot-1"}); err != nil || s.cidrs != "" {
		t.Fatalf("clearing: %v, stored %q", err, s.cidrs)
	}

	s.sets = nil
	if _, err := h.SetBotAllowlist(op, &pb.SetBotAllowlistReq{UserId: "nobody", Cidrs: []string{"10.0.0.1"}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unknown account: %v", err)
	}
	if _, err := h.SetBotAllowlist(op, &pb.SetBotAllowlistReq{UserId: "bot-1", Cidrs: []string{"nope"}}); detailOf(t, err).GetCode() != CodeBotAllowlistInvalid {
		t.Errorf("bad entry: %v", err)
	}
	s.bot.Kind = pb.AccountKind_HUMAN
	if _, err := h.GetBotGuard(op, &pb.GetBotGuardReq{UserId: "bot-1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a person: %v", err)
	}
	if len(s.sets) != 0 {
		t.Errorf("a refusal wrote %v", s.sets)
	}
}

// Only a signed-in person sets or reads a bot's guard: an API token, the
// bot's own included, is refused before anything is read or written.
func TestBotGuard_AnAPITokenCallerIsRefused(t *testing.T) {
	withoutOrgs(t)
	s := &guardStore{keyStore: newKeyStore()}
	h := &AuthServiceHandler{Query: s, Mutation: s}
	raw, err := proto.Marshal(&pb.AuthResp{UserId: "op-1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		scopeUserIDKey, "op-1", userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
	if _, err := h.SetBotAllowlist(ctx, &pb.SetBotAllowlistReq{UserId: "bot-1", Cidrs: []string{"10.0.0.1"}}); detailOf(t, err).GetCode() != CodeSessionRequired {
		t.Errorf("set: %v", err)
	}
	if _, err := h.GetBotGuard(ctx, &pb.GetBotGuardReq{UserId: "bot-1"}); detailOf(t, err).GetCode() != CodeSessionRequired {
		t.Errorf("get: %v", err)
	}
	if len(s.sets) != 0 {
		t.Error("an API-token caller wrote the allowlist")
	}
}
