package handlers

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// api_token_max_ttl_hours: a person's token always expires, never past the
// cap — whether they asked for an expiry or not, and even when the default
// says "never".
func TestPersonTokenExpiry_Cap(t *testing.T) {
	ctx := context.Background()
	h := &AuthServiceHandler{APITokenDefaultTTLHours: 0, APITokenMaxTTLHours: 24 * 30}
	limit := time.Now().Add(30 * 24 * time.Hour)

	exp, err := h.personTokenExpiry(ctx, nil)
	if err != nil || exp == nil || exp.AsTime().After(limit.Add(time.Minute)) {
		t.Fatalf("default never + cap: exp=%v err=%v", exp, err)
	}
	h.APITokenDefaultTTLHours = 24 * 365
	if exp, err = h.personTokenExpiry(ctx, nil); err != nil || exp.AsTime().After(limit.Add(time.Minute)) {
		t.Fatalf("default past the cap: exp=%v err=%v", exp, err)
	}
	h.APITokenDefaultTTLHours = 24
	if exp, err = h.personTokenExpiry(ctx, nil); err != nil || exp.AsTime().After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("default under the cap: exp=%v err=%v", exp, err)
	}
	asked := timestamppb.New(time.Now().Add(7 * 24 * time.Hour))
	if exp, err = h.personTokenExpiry(ctx, asked); err != nil || !exp.AsTime().Equal(asked.AsTime()) {
		t.Fatalf("an expiry under the cap: exp=%v err=%v", exp, err)
	}
	if _, err = h.personTokenExpiry(ctx, timestamppb.New(time.Now().Add(60*24*time.Hour))); refusalCode(t, err) != CodeExpiryTooLate {
		t.Fatalf("an expiry past the cap: %v", err)
	}

	// No cap: the behaviour before the setting — "never" stays possible.
	h = &AuthServiceHandler{APITokenDefaultTTLHours: 0}
	if exp, err = h.personTokenExpiry(ctx, nil); err != nil || exp != nil {
		t.Fatalf("no cap, default never: exp=%v err=%v", exp, err)
	}
}

// A negative cap, and a step-up asked of an activation that cannot perform
// one, fail the boot.
func TestCheckAPITokenConfig(t *testing.T) {
	if err := checkAPITokenConfig(&AuthServiceHandler{APITokenMaxTTLHours: -1}); err == nil {
		t.Fatal("a negative cap passed")
	}
	if err := checkAPITokenConfig(&AuthServiceHandler{APITokenStepUpSeconds: 300}); err != nil {
		t.Fatalf("step_up staged in this binary: %v", err)
	}
	saved := apiTokenStepUpChecks
	apiTokenStepUpChecks = nil
	defer func() { apiTokenStepUpChecks = saved }()
	if err := checkAPITokenConfig(&AuthServiceHandler{APITokenStepUpSeconds: 300}); err == nil {
		t.Fatal("a step-up without step_up passed")
	}
}
