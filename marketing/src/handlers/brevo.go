package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

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
	// events: the records go to Brevo as events (brevo_events).
	events bool
	// attributes: the records move date attributes on the contact
	// (brevo_attributes); only in a build that has its Go.
	attributes bool
	query      pb.MarketingQueryClient
	mutation   pb.MarketingMutationClient
}

// The contact attributes the plugin dates. Brevo's date attributes hold a day
// (YYYY-MM-DD) and no time.
const (
	signedUpAttr  = "W17_SIGNED_UP_AT"
	consentAtAttr = "W17_MARKETING_CONSENT_AT"
)

// brevoDate is t as a Brevo date attribute's value.
func brevoDate(t time.Time) string { return t.UTC().Format("2006-01-02") }

// attributeDef is a contact attribute the plugin writes, and its Brevo type.
type attributeDef struct{ name, typ string }

// The brevo_attributes feature's parts, set by its init; nil in a build
// without it, whose Activity table and rpcs do not exist.
var (
	// writeActivity moves the date attributes of a batch's records.
	writeActivity func(t *brevoTool, ctx context.Context, records []*w17pb.RequestEventMeta) error
	// eraseActivity forgets what an erased user did.
	eraseActivity func(t *brevoTool, ctx context.Context, user string) error
	// activityAttributes are the attributes writeActivity writes.
	activityAttributes func(t *brevoTool) []attributeDef
)

// brevoAPI is what the tool calls; *brevo.Client in production.
type brevoAPI interface {
	SendEvents(ctx context.Context, events []brevo.Event) (brevo.BatchResult, error)
	UpsertContact(ctx context.Context, extID, email string, attributes map[string]any, emailBlacklisted *bool) error
	UpdateContact(ctx context.Context, extID string, attributes map[string]any, emailBlacklisted *bool) error
	EnsureAttribute(ctx context.Context, name, typ string) error
	DeleteContact(ctx context.Context, extID string) error
	ListContacts(ctx context.Context, offset, limit int) ([]brevo.Contact, int, error)
	GetContact(ctx context.Context, extID string) (brevo.Contact, error)
	CreateContact(ctx context.Context, extID, email string, attributes map[string]any, emailBlacklisted *bool) error
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
	attributes := gen.FeatureBrevoAttributes && writeActivity != nil
	if err := deliveryChosen(gen.FeatureBrevoEvents, attributes); err != nil {
		return err
	}
	t := &brevoTool{client: client, sel: sel, consentAttr: attr, events: gen.FeatureBrevoEvents, attributes: attributes, query: clients.MarketingQuery(), mutation: clients.MarketingMutation()}
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

// deliveryChosen refuses a brevo activation that names neither way for the
// records to reach Brevo: it would boot, keep the contacts, and send nothing
// anyone asked for — which is what an activation from before brevo_events
// existed would silently become.
func deliveryChosen(events, attributes bool) error {
	if events || attributes {
		return nil
	}
	return fmt.Errorf("marketing plugin: brevo is on, and neither brevo_events nor brevo_attributes: no request would reach Brevo\n" +
		"  fix: add brevo_events (each request as an event; what brevo alone did before), brevo_attributes (each request as a date attribute on the contact, for Brevo's automations), or both to the activation's features")
}

// contactAttributes are the contact attributes the plugin writes.
func (t *brevoTool) contactAttributes() []attributeDef {
	out := []attributeDef{{t.consentAttr, "boolean"}, {consentAtAttr, "date"}, {signedUpAttr, "date"}}
	if t.attributes {
		out = append(out, activityAttributes(t)...)
	}
	return out
}

// ensureAttributes creates the contact attributes the plugin writes, in the
// background and again every interval until Brevo has them all: without one
// Brevo drops it from every write silently, and the bundle's boot must not
// wait on Brevo being reachable. One created is not asked for again.
func (t *brevoTool) ensureAttributes(every time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		todo := t.contactAttributes()
		for {
			var left []attributeDef
			for _, a := range todo {
				if err := t.client.EnsureAttribute(ctx, a.name, a.typ); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("marketing plugin: creating the Brevo contact attribute %s: %v", a.name, err)
					left = append(left, a)
				}
			}
			if todo = left; len(todo) == 0 {
				return
			}
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
