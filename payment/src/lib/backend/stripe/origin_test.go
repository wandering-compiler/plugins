package stripe

import (
	"testing"
)

// An event carries the origin mark the plugin set on the object, and its own
// creation time — what tells "ours, row not landed" from "not ours", and an
// older event from a newer one.
func TestVerifyAndParse_OriginAndCreated(t *testing.T) {
	const now = 1_700_000_000
	pinClock(t, now)
	secret := "whsec_x"
	for _, c := range []struct {
		body       string
		wantOrigin string
	}{
		{`{"id":"evt_1","type":"payment_intent.succeeded","created":1699999990,"data":{"object":{"id":"pi_1","metadata":{"w17_payment":"topup","user_id":"u"}}}}`, "topup"},
		{`{"id":"evt_2","type":"payment_intent.succeeded","created":1699999990,"data":{"object":{"id":"pi_2","metadata":{"user_id":"u"}}}}`, ""},
		{`{"id":"evt_3","type":"payment_intent.succeeded","created":1699999990,"data":{"object":{"id":"pi_3"}}}`, ""},
	} {
		body := []byte(c.body)
		ev, err := VerifyAndParse(body, sign(body, secret, itoa(now)), secret)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Origin != c.wantOrigin || ev.Created != 1699999990 {
			t.Errorf("%s: origin=%q created=%d, want %q / 1699999990", ev.ID, ev.Origin, ev.Created, c.wantOrigin)
		}
	}
}
