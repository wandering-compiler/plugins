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
	UpsertContact(ctx context.Context, extID, email string, attributes map[string]any, emailBlacklisted *bool) error
	UpdateContact(ctx context.Context, extID string, attributes map[string]any, emailBlacklisted *bool) error
	EnsureAttribute(ctx context.Context, name, typ string) error
	DeleteContact(ctx context.Context, extID string) error
	ListContacts(ctx context.Context, offset, limit int) ([]brevo.Contact, int, error)
}

// registerBrevoWebhook is the brevo_webhook feature's registration, set by
// its init; nil in a build without it.
var registerBrevoWebhook func(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet, t *brevoTool) error

func setupBrevo(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if !gen.FeatureBrevo {
		return nil
	}
	client, err := brevo.New(cfg.BrevoBaseURL, cfg.BrevoAPIKey.Reveal(), cfg.BrevoRps)
	if err != nil {
		return fmt.Errorf("marketing plugin: brevo_api_key / brevo_base_url / brevo_rps: %w", err)
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
	if registerBrevoWebhook != nil {
		if err := registerBrevoWebhook(cfg, registry, clients, t); err != nil {
			return err
		}
	}
	stopForget := t.forgetPeriodically(time.Hour)
	stopAttrs := t.ensureAttributes(time.Minute)
	stopReconcile := t.reconcileInBackground(time.Minute)
	registry.RegisterShutdown(func(context.Context) error { stopForget(); stopAttrs(); stopReconcile(); return nil })
	return nil
}

// ensureAttributes creates the contact attribute the plugin writes, in the
// background and again every interval until Brevo has it: without it Brevo
// drops the consent silently, and the bundle's boot must not wait on Brevo
// being reachable.
func (t *brevoTool) ensureAttributes(every time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			err := t.client.EnsureAttribute(ctx, t.consentAttr, "boolean")
			if err == nil || ctx.Err() != nil {
				return
			}
			log.Printf("marketing plugin: creating the Brevo contact attribute %s: %v", t.consentAttr, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
			}
		}
	}()
	return cancel
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
