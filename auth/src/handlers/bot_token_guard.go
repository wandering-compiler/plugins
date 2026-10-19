package handlers

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `bot_token_guard` feature: a machine account's
// bearer tokens can be held to an address allowlist (User.allowed_cidrs), and
// every place and method they are used from is summarised (BotTokenUse).
// Staged only when the activation enables `bot_token_guard` (plugin.yaml maps
// the feature to this file via go_files).
//
// A bearer token is the whole credential: whoever holds it acts. For a
// server's bot, whose address is fixed, an allowlist makes a copied token
// worthless anywhere else. The address is the one the gateway resolved
// through its trusted proxies (x-w17-client-addr) — the right-most hop no
// trusted proxy wrote — never the first X-Forwarded-For hop, which the client
// writes itself. The gateway strips any client-sent x-w17-* header.

// The gateway's request facts in AuthReq.headers (sdk principal.ClientAddrKey,
// SurfaceKey, MethodKey).
const (
	clientAddrKey = "x-w17-client-addr"
	methodKey     = "x-w17-method"
)

// maxAllowlistEntries bounds a list that has to fit User.allowed_cidrs.
const maxAllowlistEntries = 32

func init() {
	botBearerGuard = checkBotAllowlist
	recordBotUse = recordBotTokenUse
}

// errBotAddressRefused is the cause behind the opaque refusal of a bearer
// token used from outside its bot's allowlist. Never on the wire.
var errBotAddressRefused = errors.New("bearer token used from an address outside its machine account's allowlist")

// checkBotAllowlist refuses a bearer request whose client address is not in
// the bot's allowlist. No list: anywhere. A list and no resolved address (an
// older gateway, the CLI surface): refused — the list says where the token
// may be used, and "unknown" is not one of those places.
func checkBotAllowlist(_ context.Context, _ *AuthServiceHandler, p *authPrincipal, headers map[string]string) error {
	prefixes := parseAllowlist(p.user.GetAllowedCidrs())
	if len(prefixes) == 0 {
		return nil
	}
	addr, err := netip.ParseAddr(headers[clientAddrKey])
	if err != nil {
		return errBotAddressRefused
	}
	addr = addr.Unmap().WithZone("")
	for _, pf := range prefixes {
		if pf.Contains(addr) {
			return nil
		}
	}
	return errBotAddressRefused
}

// parseAllowlist reads a stored list. An entry that does not parse is
// skipped: the list was canonicalised when it was written, and a stored list
// that no longer parses must not widen to "anywhere" — so if NOTHING parses
// from a non-empty list, it matches nothing.
func parseAllowlist(stored string) []netip.Prefix {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return nil
	}
	var out []netip.Prefix
	for _, e := range strings.Split(stored, ",") {
		if pf, err := netip.ParsePrefix(strings.TrimSpace(e)); err == nil {
			out = append(out, pf)
		}
	}
	if len(out) == 0 {
		// Matches no address (a /32 of the unspecified address is never a
		// resolved client).
		return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 32)}
	}
	return out
}

// canonicalAllowlist turns what an operator typed into the stored form: each
// entry a masked prefix (a bare address its /32 or /128), duplicates
// dropped, order kept.
func canonicalAllowlist(ctx context.Context, entries []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		var pf netip.Prefix
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err == nil && p.Addr().Is4In6() {
				// The client address is matched unmapped, as IPv4: an
				// IPv4-mapped network must be one too, or it matches nothing.
				if p.Bits() < 96 {
					err = errors.New("an IPv4-mapped network shorter than /96")
				} else {
					p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
				}
			}
			if err != nil {
				return nil, refusal(ctx, codes.InvalidArgument, "allowlist entry "+strconv.Quote(e)+" is not a CIDR",
					CodeBotAllowlistInvalid, "cidrs", MsgBotAllowlistInvalid, map[string]string{"entry": e})
			}
			pf = p.Masked()
		} else {
			a, err := netip.ParseAddr(e)
			if err == nil && a.Zone() != "" {
				// A zone names an interface of one machine; it is no address
				// a request arrives from.
				err = errors.New("a zoned address")
			}
			if err != nil {
				return nil, refusal(ctx, codes.InvalidArgument, "allowlist entry "+strconv.Quote(e)+" is not an address",
					CodeBotAllowlistInvalid, "cidrs", MsgBotAllowlistInvalid, map[string]string{"entry": e})
			}
			a = a.Unmap()
			pf = netip.PrefixFrom(a, a.BitLen())
		}
		if s := pf.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > maxAllowlistEntries {
		return nil, refusal(ctx, codes.InvalidArgument, "allowlist has more than "+strconv.Itoa(maxAllowlistEntries)+" entries",
			CodeBotAllowlistInvalid, "cidrs", MsgBotAllowlistTooLong, map[string]string{"max": strconv.Itoa(maxAllowlistEntries)})
	}
	return out, nil
}

// botUseWindow is how often, at most, one (token, address, surface, method)
// row is written by this process — the summary answers "from where, for
// what, and since when", for which a minute is plenty.
const botUseWindow = time.Minute

// botUseSeen remembers when this process last wrote each combination. Bounded:
// past botUseSeenMax entries it is cleared, which costs at most one extra
// write per combination.
var (
	botUseMu      sync.Mutex
	botUseSeen    = map[string]time.Time{}
	botUseSeenMax = 10000
)

// recordBotTokenUse upserts the request into the bot's use summary, at most
// once per botUseWindow per combination. Best effort, like
// touchTokenLastUsed: a failed write never fails the request.
func recordBotTokenUse(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, headers map[string]string) {
	if p.usedTokenID == "" {
		return
	}
	addr := headers[clientAddrKey]
	surface := truncate(headers[surfaceKey], 16)
	method := truncate(strings.ToValidUTF8(headers[methodKey], invalidUTF8), 255)
	if a, err := netip.ParseAddr(addr); err == nil {
		addr = a.Unmap().WithZone("").String()
	} else {
		addr = ""
	}
	key := p.usedTokenID + "\x00" + addr + "\x00" + surface + "\x00" + method
	now := time.Now()
	botUseMu.Lock()
	if last, ok := botUseSeen[key]; ok && now.Sub(last) < botUseWindow {
		botUseMu.Unlock()
		return
	}
	if len(botUseSeen) >= botUseSeenMax {
		botUseSeen = map[string]time.Time{}
	}
	botUseSeen[key] = now
	botUseMu.Unlock()
	_, _ = h.Mutation.RecordBotTokenUse(ctx, &pb.RecordBotTokenUseReq{
		TokenId: p.usedTokenID,
		UserId:  p.userID,
		Address: addr,
		Surface: surface,
		Method:  method,
		UsedAt:  timestamppb.New(now),
	})
}

// SetBotAllowlist writes where a machine account's bearer tokens are
// accepted from. The operator rules of IssueBotToken: a signed-in person, a
// bot of their organization, holding no role above their own.
func (h *AuthServiceHandler) SetBotAllowlist(ctx context.Context, req *pb.SetBotAllowlistReq) (*pb.SetBotAllowlistResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	bot, err := h.operableBot(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	cidrs, err := canonicalAllowlist(ctx, req.GetCidrs())
	if err != nil {
		return nil, err
	}
	if _, err := h.Mutation.SetBotAllowedCidrs(ctx, &pb.SetBotAllowedCidrsReq{
		UserId: bot.GetId(), AllowedCidrs: strings.Join(cidrs, ","), ChangedBy: callerID, Thumbprint: requestThumbprint(ctx),
	}); err != nil {
		return nil, err
	}
	return &pb.SetBotAllowlistResp{Cidrs: cidrs}, nil
}

// GetBotGuard answers a machine account's allowlist and its use summary,
// under the same operator rules.
func (h *AuthServiceHandler) GetBotGuard(ctx context.Context, req *pb.GetBotGuardReq) (*pb.GetBotGuardResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	bot, err := h.operableBot(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	stored, err := h.Query.GetBotAllowedCidrs(ctx, &pb.GetBotAllowedCidrsReq{UserId: bot.GetId()})
	if err != nil {
		return nil, err
	}
	out := &pb.GetBotGuardResp{}
	for _, pf := range strings.Split(stored.GetAllowedCidrs(), ",") {
		if pf = strings.TrimSpace(pf); pf != "" {
			out.Cidrs = append(out.Cidrs, pf)
		}
	}
	uses, err := h.Query.ListBotTokenUses(ctx, &pb.ListBotTokenUsesReq{UserId: bot.GetId()})
	if err != nil && notFoundOK(err) != nil {
		return nil, err
	}
	for _, u := range uses.GetRows() {
		out.Uses = append(out.Uses, &pb.BotTokenUseSummary{
			TokenId: u.GetTokenId(), Address: u.GetAddress(), Surface: u.GetSurface(), Method: u.GetMethod(),
			FirstUsedAt: u.GetFirstUsedAt(), LastUsedAt: u.GetLastUsedAt(),
		})
	}
	return out, nil
}
