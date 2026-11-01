package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

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
// Every write of a contact says whether campaigns may reach it
// (emailBlacklisted), from what the plugin keeps about the user (Contact):
// Brevo subscribes a contact it is told nothing about, and an address change
// is a new address to Brevo. The plugin's state is written before Brevo, so a
// redelivery writes the same again.

// contactState is what the plugin knows of one user's contact.
type contactState struct {
	email          string
	consent        bool
	consentAt      *time.Time // nil: never told — an unknown consent, which is no consent
	unsubscribedAt *time.Time // the person unsubscribed in Brevo
	erasedAt       *time.Time // the account was erased
}

func stateOf(r *pb.ContactRow) contactState {
	return contactState{
		email:          r.GetEmail(),
		consent:        r.GetConsent(),
		consentAt:      timeOf(r.GetConsentAt()),
		unsubscribedAt: timeOf(r.GetUnsubscribedAt()),
		erasedAt:       timeOf(r.GetErasedAt()),
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

// blacklisted is the contact's emailBlacklisted: true — no campaign reaches
// it — unless the user's last known consent is a yes, decided after any
// unsubscribe in Brevo. An unknown consent is no consent: it blacklists, and
// it is never written as a false consent attribute.
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

func (t *brevoTool) onUserCreated(ctx context.Context, ev *pb.AuthUserCreated) error {
	return t.followAddress(ctx, "create the contact of", ev.GetUserId(), ev.GetEmail())
}

func (t *brevoTool) onUserUpdated(ctx context.Context, ev *pb.AuthUserUpdated) error {
	return t.followAddress(ctx, "update the contact of", ev.GetUserId(), ev.GetEmail())
}

// followAddress writes the user's address to the contact, with the
// emailBlacklisted the user's known consent gives — a new account's is
// unknown, so it is created blacklisted, and an address change never
// subscribes anyone.
func (t *brevoTool) followAddress(ctx context.Context, what, user, email string) error {
	if user == "" {
		log.Printf("marketing plugin: an auth event to %s nobody (no user id): skipped", what)
		return nil
	}
	st, err := t.loadContact(ctx, user)
	if err != nil {
		return err
	}
	if st.erasedAt != nil {
		log.Printf("marketing plugin: user %s was erased; a late event to %s them writes nothing to Brevo", user, what)
		return nil
	}
	if e := normEmail(email); e != "" && e != st.email {
		if _, err := t.mutation.SetContactEmail(ctx, &pb.SetContactEmailReq{UserId: user, Email: e}); err != nil {
			return fmt.Errorf("marketing plugin: keeping the address of user %s: %w", user, err)
		}
	}
	return t.contactCall(what, user, t.setContact(ctx, user, email, nil, st.blacklisted()))
}

// setContact writes the contact keyed by user: an update by its id (an
// address change included), or, when Brevo has no such contact yet, its
// creation. An event creates a contact too, without an address, so either
// may come first.
func (t *brevoTool) setContact(ctx context.Context, user, email string, attrs map[string]any, blacklisted bool) error {
	update := map[string]any{}
	for k, v := range attrs {
		update[k] = v
	}
	if email != "" {
		update["EMAIL"] = email
	}
	err := t.client.UpdateContact(ctx, user, update, &blacklisted)
	if brevo.IsNotFound(err) {
		return t.client.UpsertContact(ctx, user, email, attrs, &blacklisted)
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

// onConsentChanged keeps the user's decision and writes it to the contact:
// the consent attribute and emailBlacklisted = !consent (unless the person
// unsubscribed in Brevo after deciding). A decision older than the one the
// plugin holds — a redelivery overtaken by a newer one — leaves the newer
// one standing.
func (t *brevoTool) onConsentChanged(ctx context.Context, ev *pb.AuthMarketingConsentChanged) error {
	user := ev.GetUserId()
	if user == "" {
		return nil
	}
	st, err := t.loadContact(ctx, user)
	if err != nil {
		return err
	}
	if st.erasedAt != nil {
		log.Printf("marketing plugin: user %s was erased; a late consent writes nothing to Brevo", user)
		return nil
	}
	at := time.Now().UTC()
	if ev.GetDecidedAt() != nil {
		at = ev.GetDecidedAt().AsTime()
	}
	if st.consentAt != nil && at.Before(*st.consentAt) {
		at = *st.consentAt // the newer decision stands
	} else {
		if _, err := t.mutation.SetContactConsent(ctx, &pb.SetContactConsentReq{UserId: user, Consent: ev.GetConsent(), ConsentAt: timestampOf(at)}); err != nil {
			return fmt.Errorf("marketing plugin: keeping the consent of user %s: %w", user, err)
		}
		st.consent = ev.GetConsent()
	}
	st.consentAt = &at
	attrs := map[string]any{t.consentAttr: st.consent}
	return t.contactCall("set the consent of", user, t.setContact(ctx, user, "", attrs, st.blacklisted()))
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
