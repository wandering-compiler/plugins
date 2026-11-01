package handlers

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/marketing/gen"
	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
)

func init() { registerBrevoWebhook = setupBrevoWebhook }

// brevoWebhookTokenKey is the gRPC-metadata key the REST preset forwards the
// X-Brevo-Webhook-Token header under.
const brevoWebhookTokenKey = "x-brevo-webhook-token" //nolint:gosec // G101: the name of the header, not a token

// brevoWebhook serves MarketingService: Brevo's marketing webhook. An
// unsubscribe in Brevo is the person withdrawing their marketing consent; it
// is recorded on the plugin's Contact (so no later write subscribes the
// contact again) and handed to the project's consent_withdrawn hook, whose
// method records it in auth as the user's own withdrawal. auth announces it
// (MarketingConsentChanged), and the contact follows as for any withdrawal.
type brevoWebhook struct {
	pb.UnimplementedMarketingServiceServer
	token string
	tool  *brevoTool
	hooks []func(ctx context.Context, req *pb.ConsentWithdrawnReq) (*pb.ConsentWithdrawnResp, error)
}

func setupBrevoWebhook(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet, t *brevoTool) error {
	if !gen.FeatureBrevoWebhook {
		return nil
	}
	token := strings.TrimSpace(cfg.BrevoWebhookToken.Reveal())
	if token == "" {
		log.Printf("marketing plugin: brevo_webhook_token is unset: the Brevo webhook refuses every call until it is set")
	}
	registry.RegisterMarketingServiceServer(&brevoWebhook{token: token, tool: t, hooks: clients.ConsentWithdrawnHooks()})
	return nil
}

// authentic reports whether the call carries the webhook's token. Nothing is
// authentic while no token is configured.
func (w *brevoWebhook) authentic(ctx context.Context) bool {
	if w.token == "" {
		return false
	}
	md, _ := metadata.FromIncomingContext(ctx)
	got := md.Get(brevoWebhookTokenKey)
	return len(got) == 1 && subtle.ConstantTimeCompare([]byte(got[0]), []byte(w.token)) == 1
}

// brevoWebhookEvent is the part of a marketing webhook event the plugin reads.
type brevoWebhookEvent struct {
	Event     string      `json:"event"`
	Email     string      `json:"email"`
	TsEvent   json.Number `json:"ts_event"`
	DateEvent string      `json:"date_event"`
}

// at is when it happened: ts_event (unix seconds), else date_event, else now.
func (e brevoWebhookEvent) at() time.Time {
	if s, err := e.TsEvent.Int64(); err == nil && s > 0 {
		return time.Unix(s, 0).UTC()
	}
	if t, err := time.Parse("2006-01-02 15:04:05", e.DateEvent); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

// parseBrevoWebhook reads one event, or the array a batched webhook sends.
func parseBrevoWebhook(raw []byte) ([]brevoWebhookEvent, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		var evs []brevoWebhookEvent
		err := json.Unmarshal(raw, &evs)
		return evs, err
	}
	var ev brevoWebhookEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, err
	}
	return []brevoWebhookEvent{ev}, nil
}

// IngestBrevo handles one delivery. Refused without the token. Every event
// but an unsubscribe is acknowledged and ignored. A failure to record a
// withdrawal fails the delivery (Unavailable, a 5xx), which Brevo sends again;
// a delivery handled twice records the same twice.
func (w *brevoWebhook) IngestBrevo(ctx context.Context, req *pb.IngestBrevoReq) (*pb.IngestBrevoResp, error) {
	if !w.authentic(ctx) {
		return nil, status.Error(codes.Unauthenticated, "marketing plugin: the Brevo webhook token is missing or wrong")
	}
	events, err := parseBrevoWebhook(req.GetRawPayload())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "marketing plugin: a Brevo webhook body that does not parse: %v", err)
	}
	n := 0
	for _, ev := range events {
		if ev.Event != "unsubscribe" && ev.Event != "unsubscribed" {
			continue
		}
		email := normEmail(ev.Email)
		if email == "" {
			continue
		}
		got, err := w.tool.query.ListContactsByEmail(ctx, &pb.ListContactsByEmailReq{Email: email})
		if status.Code(err) == codes.InvalidArgument {
			// Not an address the table could hold: no user of the plugin's.
			log.Printf("marketing plugin: Brevo unsubscribed an address the plugin cannot look up; nothing to write back")
			continue
		}
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "marketing plugin: finding the user of an unsubscribed address: %v", err)
		}
		if len(got.GetContacts()) == 0 {
			log.Printf("marketing plugin: Brevo unsubscribed an address no user of the plugin has; nothing to write back")
			continue
		}
		for _, r := range got.GetContacts() {
			done, err := w.withdraw(ctx, r, ev.at())
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			if done {
				n++
			}
		}
	}
	return &pb.IngestBrevoResp{Unsubscribed: int32(n)}, nil
}

// withdraw records one user's unsubscribe and hands it to the project.
func (w *brevoWebhook) withdraw(ctx context.Context, r *pb.ContactRow, at time.Time) (bool, error) {
	user, st := r.GetUserId(), stateOf(r)
	if st.erasedAt != nil {
		return false, nil
	}
	if st.unsubscribedAt == nil || at.After(*st.unsubscribedAt) {
		if _, err := w.tool.mutation.SetContactUnsubscribed(ctx, &pb.SetContactUnsubscribedReq{UserId: user, UnsubscribedAt: timestamppb.New(at)}); err != nil {
			return false, fmt.Errorf("marketing plugin: recording the unsubscribe of user %s: %w", user, err)
		}
	}
	for _, h := range w.hooks {
		if _, err := h(ctx, &pb.ConsentWithdrawnReq{UserId: user, WithdrawnAt: timestamppb.New(at)}); err != nil {
			return false, fmt.Errorf("marketing plugin: the consent_withdrawn hook for user %s: %w", user, err)
		}
	}
	return true, nil
}
