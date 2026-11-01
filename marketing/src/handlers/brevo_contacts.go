package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// The contacts follow the auth plugin's accounts. A call Brevo refuses for its
// content is logged and not retried; any other failure — the network, a rate
// limit, a key or a server address the account does not accept, the plugin's
// own table — returns an error, so the event is redelivered and then
// dead-lettered, to be replayed once it is fixed.
//
// Whether campaigns may reach a contact (emailBlacklisted) follows one rule:
// the plugin writes false — subscribes — ONLY while acting on a consent=true
// decision that is the newest it knows, and only after reading the contact
// from Brevo: a contact Brevo blacklists although the plugin last left it
// subscribed is one the person unsubscribed in Brevo, which is recorded and
// not undone. Every other write sends true or leaves the field out. What the
// plugin knows (Contact) is written before Brevo, by conditional writes, and
// the Brevo value is read from the row as stored after the write — never from
// a read taken before it — so two deliveries at once, or two replicas, cannot
// let an older decision decide.

// contactState is what the plugin knows of one user's contact.
type contactState struct {
	email           string
	consent         bool
	consentAt       *time.Time // nil: never told — an unknown consent, which is no consent
	unsubscribedAt  *time.Time // the person unsubscribed in Brevo
	erasedAt        *time.Time // the account was erased
	sentBlacklisted bool       // the emailBlacklisted the plugin last wrote or found
}

func stateOf(r *pb.ContactRow) contactState {
	return contactState{
		email:           r.GetEmail(),
		consent:         r.GetConsent(),
		consentAt:       timeOf(r.GetConsentAt()),
		unsubscribedAt:  timeOf(r.GetUnsubscribedAt()),
		erasedAt:        timeOf(r.GetErasedAt()),
		sentBlacklisted: r.GetSentBlacklisted(),
	}
}

func timeOf(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	v := ts.AsTime()
	return &v
}

func timestampOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// blacklisted reports whether the contact must not be reached: true unless
// the user's last known consent is a yes, decided after any unsubscribe in
// Brevo. An unknown consent is no consent: it blacklists, and it is never
// written as a false consent attribute.
func (s contactState) blacklisted() bool {
	if s.consentAt == nil || !s.consent {
		return true
	}
	return s.unsubscribedAt != nil && !s.consentAt.After(*s.unsubscribedAt)
}

// loadContact reads what the plugin knows of user; the zero state when it
// knows nothing.
func (t *brevoTool) loadContact(ctx context.Context, user string) (contactState, error) {
	resp, err := t.query.ListContacts(ctx, &pb.ListContactsReq{UserIds: []string{user}})
	if err != nil {
		return contactState{}, fmt.Errorf("marketing plugin: reading the contact of user %s: %w", user, err)
	}
	for _, r := range resp.GetContacts() {
		if r.GetUserId() == user {
			return stateOf(r), nil
		}
	}
	return contactState{}, nil
}

func normEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// heldBack reports whether a conditional write's error is its condition
// holding it back (zero rows), which is no failure.
func heldBack(err error) bool { return status.Code(err) == codes.NotFound }

func (t *brevoTool) onUserCreated(ctx context.Context, ev *pb.AuthUserCreated) error {
	return t.followAddress(ctx, "create the contact of", ev.GetUserId(), ev.GetEmail())
}

func (t *brevoTool) onUserUpdated(ctx context.Context, ev *pb.AuthUserUpdated) error {
	return t.followAddress(ctx, "update the contact of", ev.GetUserId(), ev.GetEmail())
}

// followAddress writes the user's address to the contact. It never
// subscribes: a contact without a consent is written blacklisted (a new
// account's consent is unknown, so it is created blacklisted), and one with a
// consent keeps whatever Brevo holds — the field is left out, so an
// unsubscribe made in Brevo stands.
func (t *brevoTool) followAddress(ctx context.Context, what, user, email string) error {
	if user == "" {
		log.Printf("marketing plugin: an auth event to %s nobody (no user id): skipped", what)
		return nil
	}
	if before, err := t.loadContact(ctx, user); err != nil {
		return err
	} else if before.erasedAt != nil {
		log.Printf("marketing plugin: user %s was erased; a late event to %s them writes nothing to Brevo", user, what)
		return nil
	}
	if e := normEmail(email); e != "" {
		if _, err := t.mutation.SetContactEmail(ctx, &pb.SetContactEmailReq{UserId: user, Email: e}); err != nil {
			return fmt.Errorf("marketing plugin: keeping the address of user %s: %w", user, err)
		}
	}
	st, err := t.loadContact(ctx, user) // as stored after the write
	if err != nil {
		return err
	}
	if st.erasedAt != nil {
		log.Printf("marketing plugin: user %s was erased; a late event to %s them writes nothing to Brevo", user, what)
		return nil
	}
	if !st.blacklisted() {
		return t.contactCall(what, user, t.writeLeavingBlacklisted(ctx, user, email, nil))
	}
	if err := t.writeBlacklisted(ctx, user, email, nil); err != nil {
		return t.contactCall(what, user, err)
	}
	// A yes may have landed while this wrote: blacklisting over it would
	// leave a consented contact blacklisted. The row as stored now decides;
	// holding the newest yes, the contact is subscribed on that yes — the
	// blacklist Brevo holds is this write's own, not the person's.
	now, err := t.loadContact(ctx, user)
	if err != nil {
		return err
	}
	if now.erasedAt != nil || now.blacklisted() {
		return nil
	}
	attrs := map[string]any{t.consentAttr: now.consent}
	return t.contactCall(what, user, t.subscribe(ctx, user, attrs, now, *now.consentAt, true))
}

// writeBlacklisted writes the contact blacklisted (created when Brevo has
// none). It records that first — state, then Brevo — so a consent handler
// reading Brevo meanwhile never takes the plugin's own blacklisting for a
// person's unsubscribe.
func (t *brevoTool) writeBlacklisted(ctx context.Context, user, email string, attrs map[string]any) error {
	if err := t.recordSentBlacklisted(ctx, user, true); err != nil {
		return err
	}
	yes := true
	return t.setContact(ctx, user, email, attrs, &yes)
}

// writeLeavingBlacklisted writes the address and attributes and leaves
// emailBlacklisted as Brevo holds it. A contact Brevo does not have yet is
// created — only created, never overwritten: one the consent handler created
// meanwhile keeps its blacklist — blacklisted, unless the row as stored holds
// the newest yes the plugin has not blacklisted since (sent_blacklisted
// false, no later unsubscribe), when the field is left out as that yes left
// it.
func (t *brevoTool) writeLeavingBlacklisted(ctx context.Context, user, email string, attrs map[string]any) error {
	update := withEmail(attrs, email)
	err := t.client.UpdateContact(ctx, user, update, nil)
	if !brevo.IsNotFound(err) {
		return err
	}
	st, err := t.loadContact(ctx, user)
	if err != nil {
		return err
	}
	var blacklisted *bool
	if st.blacklisted() || st.sentBlacklisted {
		if err := t.recordSentBlacklisted(ctx, user, true); err != nil { // state first
			return err
		}
		yes := true
		blacklisted = &yes
	}
	err = t.client.CreateContact(ctx, user, email, attrs, blacklisted)
	if brevo.IsDuplicate(err) {
		return t.client.UpdateContact(ctx, user, update, nil)
	}
	return err
}

func (t *brevoTool) recordSentBlacklisted(ctx context.Context, user string, blacklisted bool) error {
	if _, err := t.mutation.SetContactSentBlacklisted(ctx, &pb.SetContactSentBlacklistedReq{UserId: user, SentBlacklisted: blacklisted}); err != nil {
		return fmt.Errorf("recording what was written to Brevo: %w", err)
	}
	return nil
}

func withEmail(attrs map[string]any, email string) map[string]any {
	update := map[string]any{}
	for k, v := range attrs {
		update[k] = v
	}
	if email != "" {
		update["EMAIL"] = email
	}
	return update
}

// setContact writes the contact keyed by user: an update by its id (an
// address change included), or, when Brevo has no such contact yet, its
// creation. An event creates a contact too, without an address, so either
// may come first.
func (t *brevoTool) setContact(ctx context.Context, user, email string, attrs map[string]any, blacklisted *bool) error {
	err := t.client.UpdateContact(ctx, user, withEmail(attrs, email), blacklisted)
	if brevo.IsNotFound(err) {
		return t.client.UpsertContact(ctx, user, email, attrs, blacklisted)
	}
	return err
}

// onUserDeleted deletes the contact and its history in Brevo: the account
// was erased, and the copy of the person's data in the tool goes with it.
// The plugin's own row loses the address and keeps the record that it was
// erased.
func (t *brevoTool) onUserDeleted(ctx context.Context, ev *pb.AuthUserDeleted) error {
	user := ev.GetUserId()
	if user == "" {
		return nil
	}
	if _, err := t.mutation.EraseContact(ctx, &pb.EraseContactReq{UserId: user}); err != nil {
		return fmt.Errorf("marketing plugin: erasing the contact of user %s: %w", user, err)
	}
	return t.contactCall("delete the contact of", user, t.client.DeleteContact(ctx, user))
}

// onConsentChanged keeps the user's decision — when it is newer than the one
// kept — and writes the contact from the row as stored after that: the
// consent attribute, and emailBlacklisted = true for a no. A yes subscribes
// only when it is the decision the row holds (the newest), and only after
// Brevo is read (subscribe).
func (t *brevoTool) onConsentChanged(ctx context.Context, ev *pb.AuthMarketingConsentChanged) error {
	user := ev.GetUserId()
	if user == "" {
		return nil
	}
	at := time.Now().UTC()
	if ev.GetDecidedAt() != nil {
		at = ev.GetDecidedAt().AsTime()
	}
	if _, err := t.mutation.EnsureContact(ctx, &pb.EnsureContactReq{UserId: user}); err != nil {
		return fmt.Errorf("marketing plugin: keeping the consent of user %s: %w", user, err)
	}
	if _, err := t.mutation.SetContactConsent(ctx, &pb.SetContactConsentReq{UserId: user, Consent: ev.GetConsent(), ConsentAt: timestampOf(at)}); err != nil && !heldBack(err) {
		return fmt.Errorf("marketing plugin: keeping the consent of user %s: %w", user, err)
	}
	st, err := t.loadContact(ctx, user) // as stored after the write
	if err != nil {
		return err
	}
	if st.erasedAt != nil {
		log.Printf("marketing plugin: user %s was erased; a late consent writes nothing to Brevo", user)
		return nil
	}
	if st.consentAt == nil {
		return fmt.Errorf("marketing plugin: the consent of user %s was not kept", user)
	}
	attrs := map[string]any{t.consentAttr: st.consent}
	newest := st.consentAt.Equal(at) && st.consent == ev.GetConsent()
	switch {
	case st.blacklisted():
		return t.contactCall("set the consent of", user, t.writeBlacklisted(ctx, user, "", attrs))
	case !newest:
		// A yes is kept, but this delivery is not it: it decides nothing.
		return t.contactCall("set the consent of", user, t.writeLeavingBlacklisted(ctx, user, "", attrs))
	}
	return t.contactCall("set the consent of", user, t.subscribe(ctx, user, attrs, st, at, false))
}

// subscribe acts on the newest decision, a yes. Brevo is read first: a
// contact it blacklists while the plugin last left it subscribed is one the
// person unsubscribed in Brevo since — recorded, and not undone. After the
// write the row is read again, and a no (or an unsubscribe) that overtook
// this one meanwhile blacklists the contact again.
//
// ownBlacklist: the caller blacklisted the contact itself just now, so a
// blacklist Brevo answers is that write, never a person's unsubscribe.
func (t *brevoTool) subscribe(ctx context.Context, user string, attrs map[string]any, st contactState, at time.Time, ownBlacklist bool) error {
	no := false
	got, err := t.client.GetContact(ctx, user)
	switch {
	case brevo.IsNotFound(err):
		if err := t.client.UpsertContact(ctx, user, "", attrs, &no); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if err == nil && got.EmailBlacklisted && !ownBlacklist {
		// Re-read after Brevo answered: the plugin records its own
		// blacklisting before writing it, so a write that landed during the
		// read (a sign-up's UserCreated) shows here, and is not taken for the
		// person unsubscribing.
		if st, err = t.loadContact(ctx, user); err != nil {
			return err
		}
	}
	switch {
	case err == nil && got.EmailBlacklisted && !st.sentBlacklisted && !ownBlacklist:
		log.Printf("marketing plugin: user %s unsubscribed in Brevo; their consent does not subscribe them again", user)
		if _, err := t.mutation.SetContactUnsubscribed(ctx, &pb.SetContactUnsubscribedReq{UserId: user, UnsubscribedAt: timestampOf(time.Now().UTC())}); err != nil && !heldBack(err) {
			return fmt.Errorf("recording the unsubscribe: %w", err)
		}
		if err := t.recordSentBlacklisted(ctx, user, true); err != nil {
			return err
		}
		return t.client.UpdateContact(ctx, user, attrs, nil)
	case err == nil:
		if err := t.client.UpdateContact(ctx, user, attrs, &no); err != nil {
			return err
		}
	}
	if err := t.recordSentBlacklisted(ctx, user, false); err != nil {
		return err
	}
	now, err := t.loadContact(ctx, user)
	if err != nil {
		return err
	}
	if now.erasedAt == nil && now.blacklisted() {
		return t.writeBlacklisted(ctx, user, "", map[string]any{t.consentAttr: now.consent})
	}
	return nil
}

func (t *brevoTool) contactCall(what, user string, err error) error {
	if err == nil {
		return nil
	}
	if user == "" || brevo.Refused(err) {
		log.Printf("marketing plugin: Brevo refused to %s user %s: %v", what, user, err)
		return nil
	}
	return fmt.Errorf("marketing plugin: %s user %s: %w", what, user, err)
}
