package handlers

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// Every way an inbound webhook can fail authentication must get the same
// opaque Unauthenticated, and must not touch the store: no
// reconciliation, no ledger row. Driven end to end through IngestStripe
// (metadata → driver verification → handler) over a real local payment,
// so a delivery that slipped through would visibly flip its status.
func TestIngestStripe_AuthenticationRefusals(t *testing.T) {
	now := time.Now().Unix()
	r := newRig(t)
	pid := r.charge("user-a", "10.00", "o-sig").GetProviderPaymentId()
	body := eventJSON("evt_sig", "payment_intent.succeeded", pid, nil)
	good := signedAt(body, testWebhookSecret, now)
	v1 := good[strings.Index(good, "v1="):]

	cases := []struct {
		name string
		body []byte
		sig  string
		md   bool // false = no metadata at all
	}{
		{"no metadata", body, "", false},
		{"empty header", body, "", true},
		{"timestamp only", body, "t=" + itoa(now), true},
		{"signature only", body, v1, true},
		{"wrong secret", body, signedAt(body, "whsec_attacker", now), true},
		{"body tampered after signing", []byte(strings.Replace(string(body), pid, "pi_other", 1)), good, true},
		{"v0 scheme only", body, strings.Replace(good, "v1=", "v0=", 1), true},
		{"signature not hex", body, "t=" + itoa(now) + ",v1=zz" + strings.Repeat("0", 62), true},
		{"truncated signature", body, good[:len(good)-2], true},
		{"replayed: signed 6 minutes ago", body, signedAt(body, testWebhookSecret, now-360), true},
		{"future: signed 6 minutes ahead", body, signedAt(body, testWebhookSecret, now+360), true},
		{"timestamp swapped after signing", body, "t=" + itoa(now+1) + "," + v1, true},
		{"signed event without an id", eventJSON("", "payment_intent.succeeded", pid, nil), signedAt(eventJSON("", "payment_intent.succeeded", pid, nil), testWebhookSecret, now), true},
		{"signed event without a type", eventJSON("evt_x", "", pid, nil), signedAt(eventJSON("evt_x", "", pid, nil), testWebhookSecret, now), true},
		{"signed body that is not JSON", []byte("not json"), signedAt([]byte("not json"), testWebhookSecret, now), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			if c.md {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("stripe-signature", c.sig))
			}
			_, err := r.h.IngestStripe(ctx, &pb.IngestStripeReq{RawPayload: c.body})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("want Unauthenticated, got %v", err)
			}
			if msg := status.Convert(err).Message(); msg != "invalid webhook signature" {
				t.Errorf("message %q — every refusal must read the same", msg)
			}
		})
	}
	if r.store.callCount("MarkPaymentSucceeded") != 0 || r.store.count("processed") != 0 {
		t.Fatal("an unauthenticated delivery reached the store")
	}
	if st := r.store.paymentStatus(t, pid); st != pb.Payment_REQUIRES_ACTION {
		t.Fatalf("status = %v", st)
	}

	// Control: the same event, correctly signed, is accepted — so the
	// refusals above were for the stated reason.
	if _, err := r.deliverSigned(body, good); err != nil {
		t.Fatalf("control delivery: %v", err)
	}
}

// Secret rotation: Stripe signs with every active secret and sends one
// v1 per secret; one match is enough. Extra unknown keys are ignored.
func TestIngestStripe_RotatedSecretsAndExtraHeaderParts(t *testing.T) {
	r := newRig(t)
	pid := r.charge("user-a", "1.00", "rot").GetProviderPaymentId()
	body := eventJSON("evt_rot", "payment_intent.succeeded", pid, nil)
	now := time.Now().Unix()
	old := signedAt(body, "whsec_old_retired", now)
	cur := signedAt(body, testWebhookSecret, now)
	header := " t=" + itoa(now) + " , v1=" + old[strings.Index(old, "v1=")+3:] + ",v1=" + cur[strings.Index(cur, "v1=")+3:] + ",v0=deadbeef,junk"
	resp, err := r.deliverSigned(body, header)
	if err != nil || !resp.GetHandled() {
		t.Fatalf("handled=%v err=%v", resp.GetHandled(), err)
	}
}

// An unconfigured signing secret must fail CLOSED — an empty secret is
// not "skip verification", and a header HMAC'd with the empty key must
// not pass either.
func TestIngestStripe_UnconfiguredSecretFailsClosed(t *testing.T) {
	r := newRig(t)
	r.h.WebhookSecret = ""
	pid := r.charge("user-a", "1.00", "nosecret").GetProviderPaymentId()
	body := eventJSON("evt_ns", "payment_intent.succeeded", pid, nil)
	_, err := r.deliverSigned(body, signedAt(body, "", time.Now().Unix()))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	if r.store.count("processed") != 0 {
		t.Error("store touched")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
