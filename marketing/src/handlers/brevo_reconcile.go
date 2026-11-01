package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// The contacts the plugin created before it wrote emailBlacklisted are all
// subscribed to campaigns, consent or none. A one-time pass blacklists every
// contact of the plugin's whose user has not consented, once per deployment:
// in the background (Brevo being slow or unreachable never holds up the boot),
// retried until it finishes, and recorded (Reconciliation) so neither a restart
// nor a second replica runs it again. A replica claims it and renews the claim
// page by page; a claim not renewed within reconcileLease is taken over, since
// its replica is gone.
//
// It only ever blacklists. A contact Brevo already blacklists may be one the
// person unsubscribed in Brevo, which the plugin could not hear of before its
// webhook existed, so the pass never subscribes anyone; what decides "has not
// consented" is the plugin's own Contact when it knows the user, else the
// consent attribute the plugin wrote to the contact (true = consented). A
// contact without an EXT_ID that is a user id is not the plugin's — a form's
// subscriber, an import — and is left alone.

const (
	reconcileBlacklistName = "brevo_email_blacklisted_v1"
	reconcileLease         = 10 * time.Minute
	reconcilePage          = 500
	maxReconcilePasses     = 10
)

// errReconcileElsewhere: another replica holds the job (or took it over).
var errReconcileElsewhere = errors.New("another replica is running it")

var userIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func newOwnerID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("pid-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// reconcileInBackground runs the pass until it is done — here or on another
// replica — retrying every interval, until the returned stop is called.
func (t *brevoTool) reconcileInBackground(every time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	owner := newOwnerID()
	go func() {
		for {
			done, err := t.reconcileBlacklist(ctx, owner)
			if done || ctx.Err() != nil {
				return
			}
			if err != nil && !errors.Is(err, errReconcileElsewhere) {
				log.Printf("marketing plugin: blacklisting the Brevo contacts without consent (retried): %v", err)
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

// reconcileBlacklist runs the pass once if this replica can claim it. done
// is true when the pass is finished, by this replica or another.
func (t *brevoTool) reconcileBlacklist(ctx context.Context, owner string) (done bool, err error) {
	claimed, done, err := t.claimReconciliation(ctx, owner)
	if err != nil || done {
		return done, err
	}
	if !claimed {
		return false, errReconcileElsewhere
	}
	// Brevo pages by offset, and a contact deleted while the pass runs shifts
	// every later one a place back, past the page boundary: one is skipped.
	// So the pass repeats until one blacklists nothing while the account's
	// count held still — every contact was seen, subscribed-and-consented or
	// blacklisted — and only then is done.
	reviewed, blacklisted := 0, 0
	for pass := 1; ; pass++ {
		r, n, steady, err := t.reconcilePass(ctx, owner)
		if err != nil {
			return false, err
		}
		reviewed, blacklisted = reviewed+r, blacklisted+n
		if n == 0 && steady {
			break
		}
		if pass == maxReconcilePasses {
			return false, fmt.Errorf("%d passes and the contacts are still changing under it; the next run goes on", pass)
		}
		if err := t.renewReconciliation(ctx, owner); err != nil {
			return false, err
		}
	}
	if _, err := t.mutation.FinishReconciliation(ctx, &pb.ReconciliationOwnerReq{Name: reconcileBlacklistName, Owner: owner}); err != nil {
		if status.Code(err) == codes.NotFound {
			return false, errReconcileElsewhere
		}
		return false, fmt.Errorf("recording the pass as done: %w", err)
	}
	log.Printf("marketing plugin: Brevo contacts reconciled: %d reviewed, %d blacklisted for want of consent", reviewed, blacklisted)
	return true, nil
}

// reconcilePass reviews every page once; it answers how many contacts it
// reviewed and blacklisted, and whether the account's count held still
// through it (a deletion mid-pass can make offset paging skip a contact).
func (t *brevoTool) reconcilePass(ctx context.Context, owner string) (reviewed, blacklisted int, steady bool, err error) {
	first := -1
	for offset := 0; ; {
		page, total, err := t.client.ListContacts(ctx, offset, reconcilePage)
		if err != nil {
			return reviewed, blacklisted, false, fmt.Errorf("listing the Brevo contacts at %d: %w", offset, err)
		}
		if first < 0 {
			first = total
		}
		n, err := t.blacklistWithoutConsent(ctx, page)
		if err != nil {
			return reviewed, blacklisted, false, err
		}
		reviewed, blacklisted = reviewed+len(page), blacklisted+n
		offset += len(page)
		if len(page) == 0 || offset >= total {
			return reviewed, blacklisted, total == first, nil
		}
		if err := t.renewReconciliation(ctx, owner); err != nil {
			return reviewed, blacklisted, false, err
		}
	}
}

func (t *brevoTool) renewReconciliation(ctx context.Context, owner string) error {
	if _, err := t.mutation.RenewReconciliation(ctx, &pb.ReconciliationOwnerReq{Name: reconcileBlacklistName, Owner: owner}); err != nil {
		if status.Code(err) == codes.NotFound {
			return errReconcileElsewhere
		}
		return fmt.Errorf("renewing the claim: %w", err)
	}
	return nil
}

// claimReconciliation claims the pass: new, held by this owner already, or
// left by a replica that stopped renewing it. done when it is finished.
func (t *brevoTool) claimReconciliation(ctx context.Context, owner string) (claimed, done bool, err error) {
	_, err = t.mutation.ClaimReconciliation(ctx, &pb.ClaimReconciliationReq{Name: reconcileBlacklistName, Owner: owner})
	if err == nil {
		return true, false, nil
	}
	if !isUniqueViolation(err) {
		return false, false, fmt.Errorf("claiming the pass: %w", err)
	}
	_, err = t.mutation.TakeOverReconciliation(ctx, &pb.TakeOverReconciliationReq{
		Name: reconcileBlacklistName, Owner: owner, StaleBefore: timestamppb.New(time.Now().Add(-reconcileLease)),
	})
	if err == nil {
		return true, false, nil
	}
	if status.Code(err) != codes.NotFound {
		return false, false, fmt.Errorf("taking the pass over: %w", err)
	}
	got, err := t.query.GetReconciliation(ctx, &pb.GetReconciliationReq{Name: reconcileBlacklistName})
	if err != nil {
		return false, false, fmt.Errorf("reading the pass: %w", err)
	}
	return false, got.GetFinishedAt() != nil, nil
}

// blacklistWithoutConsent blacklists the contacts of a page that are the
// plugin's, subscribed, and whose user has not consented; it answers how many.
func (t *brevoTool) blacklistWithoutConsent(ctx context.Context, page []brevo.Contact) (int, error) {
	var ids []string
	for _, c := range page {
		if !c.EmailBlacklisted && userIDRe.MatchString(c.ExtID) {
			ids = append(ids, c.ExtID)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	known, err := t.query.ListContacts(ctx, &pb.ListContactsReq{UserIds: ids})
	if err != nil {
		return 0, fmt.Errorf("reading the contacts of %d users: %w", len(ids), err)
	}
	states := map[string]contactState{}
	for _, r := range known.GetContacts() {
		states[r.GetUserId()] = stateOf(r)
	}
	yes, n := true, 0
	for _, c := range page {
		if c.EmailBlacklisted || !userIDRe.MatchString(c.ExtID) {
			continue
		}
		if st, ok := states[c.ExtID]; ok && (st.consentAt != nil || st.unsubscribedAt != nil || st.erasedAt != nil) {
			if !st.blacklisted() {
				continue
			}
		} else if consented(c.Attributes[t.consentAttr]) {
			continue
		}
		err := t.client.UpdateContact(ctx, c.ExtID, nil, &yes)
		if brevo.Refused(err) || brevo.IsNotFound(err) {
			log.Printf("marketing plugin: Brevo refused to blacklist the contact of user %s: %v", c.ExtID, err)
			continue
		}
		if err != nil {
			return n, fmt.Errorf("blacklisting the contact of user %s: %w", c.ExtID, err)
		}
		if err := t.recordSentBlacklisted(ctx, c.ExtID, true); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// consented reads the consent attribute as Brevo answers a boolean one.
func consented(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}
