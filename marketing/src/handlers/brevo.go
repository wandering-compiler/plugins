package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/marketing/gen"
	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

func init() { registerBrevo = setupBrevo }

// sentRetention is how long a sent record's id is remembered. The stream
// redelivers a failed batch within minutes (a few attempts with backoff), so
// three days is far past the last redelivery of anything the plugin sent.
const sentRetention = 72 * time.Hour

// brevoTool is the brevo feature: the request consumer and the contact
// subscriptions over one client.
type brevoTool struct {
	client      brevoAPI
	sel         selection
	consentAttr string
	query       pb.MarketingQueryClient
	mutation    pb.MarketingMutationClient
}

// brevoAPI is what the tool calls; *brevo.Client in production.
type brevoAPI interface {
	SendEvents(ctx context.Context, events []brevo.Event) (brevo.BatchResult, error)
	UpsertContact(ctx context.Context, extID, email string, attributes map[string]any) error
	DeleteContact(ctx context.Context, extID string) error
}

func setupBrevo(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if !gen.FeatureBrevo {
		return nil
	}
	client, err := brevo.New(cfg.BrevoBaseURL, cfg.BrevoAPIKey.Reveal(), cfg.BrevoRps)
	if err != nil {
		return fmt.Errorf("marketing plugin: <DOMAIN>_MARKETING_BREVO_API_KEY / _BREVO_BASE_URL / _BREVO_RPS: %w", err)
	}
	reads := map[string]bool{}
	for m, k := range clients.RequestMethods() {
		if k.Marketing {
			reads[m] = k.Read
		}
	}
	sel, err := newSelection(cfg.Send, cfg.Include, cfg.Exclude, reads)
	if err != nil {
		return err
	}
	attr := strings.TrimSpace(cfg.BrevoConsentAttribute)
	if attr == "" {
		attr = "W17_MARKETING_CONSENT"
	}
	t := &brevoTool{client: client, sel: sel, consentAttr: attr, query: clients.MarketingQuery(), mutation: clients.MarketingMutation()}
	if err := registry.RegisterMarketingConsumer("brevo", t); err != nil {
		return err
	}
	for _, register := range []func() error{
		func() error { return registry.OnAuthUserCreated(t.onUserCreated) },
		func() error { return registry.OnAuthUserUpdated(t.onUserUpdated) },
		func() error { return registry.OnAuthUserDeleted(t.onUserDeleted) },
		func() error { return registry.OnAuthMarketingConsentChanged(t.onConsentChanged) },
	} {
		if err := register(); err != nil {
			return err
		}
	}
	stop := t.forgetPeriodically(time.Hour)
	registry.RegisterShutdown(func(context.Context) error { stop(); return nil })
	return nil
}

// forgetPeriodically drops sent ids past their retention every interval,
// until the returned stop is called.
func (t *brevoTool) forgetPeriodically(every time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				before := timestamppb.New(time.Now().Add(-sentRetention))
				if _, err := t.mutation.ForgetSentEventsBefore(ctx, &pb.ForgetSentEventsBeforeReq{Before: before}); err != nil && ctx.Err() == nil {
					log.Printf("marketing plugin: forgetting sent records: %v", err)
				}
			}
		}
	}()
	return cancel
}
