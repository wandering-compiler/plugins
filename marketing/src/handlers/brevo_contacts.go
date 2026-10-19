package handlers

import (
	"context"
	"fmt"
	"log"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// The contacts follow the auth plugin's accounts. A call Brevo refuses for its
// content is logged and not retried; any other failure — the network, a rate
// limit, a key or a server address the account does not accept — returns an
// error, so the event is redelivered and then dead-lettered, to be replayed
// once it is fixed.

func (t *brevoTool) onUserCreated(ctx context.Context, ev *pb.AuthUserCreated) error {
	return t.contactCall("create the contact of", ev.GetUserId(), t.client.UpsertContact(ctx, ev.GetUserId(), ev.GetEmail(), nil))
}

func (t *brevoTool) onUserUpdated(ctx context.Context, ev *pb.AuthUserUpdated) error {
	return t.contactCall("update the contact of", ev.GetUserId(), t.client.UpsertContact(ctx, ev.GetUserId(), ev.GetEmail(), nil))
}

// onUserDeleted deletes the contact and its history in Brevo: the account
// was erased, and the copy of the person's data in the tool goes with it.
func (t *brevoTool) onUserDeleted(ctx context.Context, ev *pb.AuthUserDeleted) error {
	return t.contactCall("delete the contact of", ev.GetUserId(), t.client.DeleteContact(ctx, ev.GetUserId()))
}

func (t *brevoTool) onConsentChanged(ctx context.Context, ev *pb.AuthMarketingConsentChanged) error {
	attrs := map[string]any{t.consentAttr: ev.GetConsent()}
	return t.contactCall("set the consent of", ev.GetUserId(), t.client.UpsertContact(ctx, ev.GetUserId(), "", attrs))
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
