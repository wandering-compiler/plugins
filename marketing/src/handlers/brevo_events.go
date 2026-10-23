package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/wandering-compiler/sdk/go/lib/eventlog"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// ConsumeMarketing sends a batch of the gateway's marketing records to Brevo
// as events.
//
// The stream delivers a batch at least once, and Brevo has no idempotency key,
// so a record already sent is skipped (SentEvent), and a record is recorded
// as sent only once Brevo accepted it. A transient failure returns an error
// and the stream redelivers the batch; what was sent before it is skipped
// then. An event Brevo refuses for its content is logged and not retried:
// sending it again would be refused again.
func (t *brevoTool) ConsumeMarketing(ctx context.Context, batch *eventlog.ConsumedBatch) error {
	type pending struct {
		id    string
		event brevo.Event
	}
	var todo []pending
	var ids []string
	for _, rec := range batch.Records {
		meta := rec.Meta
		if meta == nil || !t.sel.sends(meta.GetMethod()) {
			continue
		}
		ev, ok := eventFor(meta, t.consentAttr)
		if !ok {
			continue
		}
		id := hex.EncodeToString(meta.GetId())
		todo = append(todo, pending{id: id, event: ev})
		ids = append(ids, id)
	}
	if len(todo) == 0 {
		return nil
	}
	sent, err := t.query.ListSentEvents(ctx, &pb.ListSentEventsReq{Ids: ids})
	if err != nil {
		return fmt.Errorf("marketing plugin: which records were sent: %w", err)
	}
	done := map[string]bool{}
	for _, id := range sent.GetIds() {
		done[id] = true
	}
	var chunk []pending
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		events := make([]brevo.Event, len(chunk))
		for i, p := range chunk {
			events[i] = p.event
		}
		res, err := t.client.SendEvents(ctx, events)
		if err != nil {
			return fmt.Errorf("marketing plugin: sending %d events to Brevo: %w", len(events), err)
		}
		for i, p := range chunk {
			if reason, refused := res.Failed[i]; refused {
				log.Printf("marketing plugin: Brevo refused event %s (record %s): %s", p.event.EventName, p.id, reason)
			}
			// Refused or accepted, it is not to be sent again.
			if err := t.recordSent(ctx, p.id); err != nil {
				return err
			}
		}
		chunk = chunk[:0]
		return nil
	}
	size := 0
	for _, p := range todo {
		if done[p.id] {
			continue
		}
		n := approxSize(p.event)
		if len(chunk) == brevo.MaxBatchEvents || (len(chunk) > 0 && size+n > brevo.MaxBatchBytes*9/10) {
			if err := flush(); err != nil {
				return err
			}
			size = 0
		}
		chunk = append(chunk, p)
		size += n
	}
	return flush()
}

// recordSent remembers a record as sent; one a concurrent replica recorded
// first is the same outcome.
func (t *brevoTool) recordSent(ctx context.Context, id string) error {
	_, err := t.mutation.RecordSentEvent(ctx, &pb.RecordSentEventReq{Id: id})
	if err != nil && !isUniqueViolation(err) {
		return fmt.Errorf("marketing plugin: recording record %s as sent: %w", id, err)
	}
	return nil
}

var eventNameRe = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// eventName is the Brevo event a method's record becomes: `<Service>_<Method>`
// (`/e2e.app.tasks.TasksBusiness/CreateTask` → `TasksBusiness_CreateTask`),
// in the characters Brevo accepts.
func eventName(method string) string {
	svc, name, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	if i := strings.LastIndex(svc, "."); i >= 0 {
		svc = svc[i+1:]
	}
	n := eventNameRe.ReplaceAllString(svc+"_"+name, "_")
	if len(n) > 255 {
		n = n[:255]
	}
	return n
}

// eventFor is the Brevo event a record becomes, keyed by the user's id;
// false for a record of nobody (marketing records are signed-in only, so
// this is defensive).
func eventFor(meta *w17pb.RequestEventMeta, consentAttr string) (brevo.Event, bool) {
	user := meta.GetUserId()
	if user == "" {
		return brevo.Event{}, false
	}
	props := map[string]any{
		"w17_api":         strings.ToLower(strings.TrimPrefix(meta.GetApi().String(), "REQUEST_API_")),
		"w17_duration_ms": meta.GetDurationMicros() / 1000,
	}
	if s := meta.GetHttpStatus(); s != 0 {
		props["w17_status"] = s
	} else {
		props["w17_grpc_code"] = meta.GetGrpcCode()
	}
	if r := meta.GetRoute(); r != "" {
		props["w17_route"] = r
	}
	// The organization the request acted in and the caller's kind of
	// membership there (the account type) are the request's, not the
	// person's: one user may work in two organizations at once, as staff of
	// one and a client of the other. On the event, never on the contact,
	// where the last request would overwrite the one before. Absent when the
	// project has no organizations or no kinds.
	if org := meta.GetOrgId(); org != "" {
		props["w17_org_id"] = org
	}
	if kind := meta.GetMembershipKind(); kind != "" {
		props["w17_account_type"] = kind
	}
	if meta.GetTruncated() {
		props["w17_truncated"] = true
	}
	if c := meta.GetClient(); c != nil {
		for k, v := range c.GetUtm() {
			props["utm_"+eventNameRe.ReplaceAllString(k, "_")] = v
		}
		if r := c.GetReferrer(); r != "" {
			props["referrer"] = r
		}
	}
	contact := map[string]any{}
	if meta.MarketingConsent != nil {
		contact[consentAttr] = meta.GetMarketingConsent()
	}
	ev := brevo.Event{
		EventName:       eventName(meta.GetMethod()),
		Identifiers:     brevo.Identifiers{ExtID: user},
		EventProperties: props,
	}
	if st := meta.GetStart(); st != nil {
		ev.EventDate = st.AsTime().UTC().Format(time.RFC3339Nano)
	}
	if len(contact) > 0 {
		ev.ContactProperties = contact
	}
	return ev, true
}

// approxSize estimates an event's share of a batch body.
func approxSize(ev brevo.Event) int {
	n := 128 + len(ev.EventName) + len(ev.Identifiers.ExtID)
	for k, v := range ev.EventProperties {
		n += len(k) + len(fmt.Sprint(v)) + 8
	}
	for k, v := range ev.ContactProperties {
		n += len(k) + len(fmt.Sprint(v)) + 8
	}
	return n
}
