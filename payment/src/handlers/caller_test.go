package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// envelope marshals an auth response the way a project's AuthResp would:
// permission ids at 1, the caller at 2, something else at 3.
func envelope(uid string) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, []byte{5, 7})
	if uid != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, uid)
	}
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendString(b, "scope")
	return b
}

// asCaller is a request that came through the gateway for uid.
func asCaller(uid string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(callerMetadataKey, base64.StdEncoding.EncodeToString(envelope(uid))))
}

func TestUserIDField_ReadsField2AmongOthers(t *testing.T) {
	if got := userIDField(envelope("user-a")); got != "user-a" {
		t.Errorf("userIDField = %q, want user-a", got)
	}
	if got := userIDField(envelope("")); got != "" {
		t.Errorf("an envelope with no field 2 read as %q", got)
	}
	if got := userIDField([]byte{0x12, 0x7f}); got != "" {
		t.Errorf("a truncated envelope read as %q", got)
	}
}

func TestActingFor(t *testing.T) {
	broken := metadata.NewIncomingContext(context.Background(), metadata.Pairs(callerMetadataKey, "%%%"))
	noID := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(callerMetadataKey, base64.StdEncoding.EncodeToString(envelope(""))))
	empty := metadata.NewIncomingContext(context.Background(), metadata.Pairs(callerMetadataKey, ""))
	repeated := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		callerMetadataKey, "",
		callerMetadataKey, base64.StdEncoding.EncodeToString(envelope("user-a"))))
	for _, c := range []struct {
		name      string
		ctx       context.Context
		requested string
		want      string
		code      codes.Code
	}{
		{"the project's own code names the user", context.Background(), "user-b", "user-b", codes.OK},
		{"the caller, named", asCaller("user-a"), "user-a", "user-a", codes.OK},
		{"the caller, by default", asCaller("user-a"), "", "user-a", codes.OK},
		{"someone else", asCaller("user-a"), "user-b", "", codes.PermissionDenied},
		{"an undecodable envelope is not an internal call", broken, "user-b", "", codes.Unauthenticated},
		{"an envelope without a caller is not an internal call", noID, "user-b", "", codes.Unauthenticated},
		{"an empty envelope is not an internal call", empty, "user-b", "", codes.Unauthenticated},
		{"a repeated envelope is not an internal call", repeated, "user-b", "", codes.Unauthenticated},
	} {
		got, err := actingFor(c.ctx, c.requested)
		if code := status.Code(err); code != c.code || got != c.want {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, code, c.want, c.code)
		}
	}
}

// A signed-in caller cannot charge someone else, and nothing reaches the
// provider when it tries.
func TestCreatePayment_ASignedInCallerCannotChargeAnotherUser(t *testing.T) {
	r := newRig(t)
	_, err := r.h.CreatePayment(asCaller("user-a"), &pb.ChargeReq{UserId: "user-b", Amount: "5.00", Currency: "usd"})
	wantCode(t, err, codes.PermissionDenied, "charge for another user")
	if n := r.stripe.count("/v1/payment_intents"); n != 0 {
		t.Errorf("provider intents = %d, want 0", n)
	}
}

func TestCreateCustomerAndSubscribe_RefuseAnotherUser(t *testing.T) {
	r := newRig(t)
	_, err := r.h.CreateCustomer(asCaller("user-a"), &pb.NewCustomerReq{UserId: "user-b", Email: "b@example.test"})
	wantCode(t, err, codes.PermissionDenied, "customer for another user")
	_, err = r.h.Subscribe(asCaller("user-a"), &pb.SubscribeReq{UserId: "user-b", PlanSlug: "pro"})
	wantCode(t, err, codes.PermissionDenied, "subscription for another user")
	_, err = r.h.TopUpCredit(asCaller("user-a"), &pb.TopUpCreditReq{UserId: "user-b", Amount: "5.00", Currency: "usd"})
	wantCode(t, err, codes.PermissionDenied, "top-up for another user")
}

// A caller reads their own payment; another person's reads as not found,
// and the read requires a signed-in caller.
func TestGetMyPayment_OnlyTheOwnersPayment(t *testing.T) {
	r := newRig(t)
	resp, err := r.h.CreatePayment(asCaller("user-a"), &pb.ChargeReq{Amount: "5.00", Currency: "usd"})
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	id := resp.GetPayment().GetId()
	if _, err := r.h.CreateCustomer(context.Background(), &pb.NewCustomerReq{UserId: "user-b", Email: "b@example.test"}); err != nil {
		t.Fatalf("customer b: %v", err)
	}

	got, err := r.h.GetMyPayment(asCaller("user-a"), &pb.GetMyPaymentReq{Id: id})
	if err != nil || got.GetPayment().GetId() != id {
		t.Fatalf("owner read: %v, %+v", err, got)
	}
	_, err = r.h.GetMyPayment(asCaller("user-b"), &pb.GetMyPaymentReq{Id: id})
	wantCode(t, err, codes.NotFound, "another customer's payment")
	_, err = r.h.GetMyPayment(asCaller("user-c"), &pb.GetMyPaymentReq{Id: id})
	wantCode(t, err, codes.NotFound, "a caller who is no customer")
	_, err = r.h.GetMyPayment(context.Background(), &pb.GetMyPaymentReq{Id: id})
	wantCode(t, err, codes.Unauthenticated, "no signed-in caller")
}

// The caller's own reads take no user from the request at all, and need a
// signed-in caller.
func TestGetMyReads_RequireASignedInCaller(t *testing.T) {
	r := newRig(t)
	_, err := r.h.GetMyCreditBalance(context.Background(), &pb.GetMyCreditBalanceReq{})
	wantCode(t, err, codes.Unauthenticated, "balance without a caller")
	_, err = r.h.GetMyUsageMeter(context.Background(), &pb.GetMyUsageMeterReq{Meter: "api", Period: "2026-10"})
	wantCode(t, err, codes.Unauthenticated, "usage without a caller")
	_, err = r.h.GetMySubscription(context.Background(), &pb.GetMySubscriptionReq{Id: "00000000-0000-0000-0000-000000000001"})
	wantCode(t, err, codes.Unauthenticated, "subscription without a caller")
	_, err = r.h.GetMySubscription(asCaller("user-a"), &pb.GetMySubscriptionReq{Id: "00000000-0000-0000-0000-000000000001"})
	wantCode(t, err, codes.NotFound, "a subscription that is not the caller's")
}

// Each caller reads their own balance and meter, never another person's.
func TestGetMyBalanceAndMeter_TheCallersOwn(t *testing.T) {
	r := newRig(t)
	for _, g := range []struct{ user, amount string }{{"user-a", "10"}, {"user-b", "3"}} {
		if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: g.user, Amount: g.amount, IdempotencyKey: "g-" + g.user}); err != nil {
			t.Fatalf("grant %s: %v", g.user, err)
		}
		if _, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: g.user, Meter: "api", Period: "2026-10", Quantity: int64(len(g.amount)), IdempotencyKey: "u-" + g.user}); err != nil {
			t.Fatalf("usage %s: %v", g.user, err)
		}
	}
	bal, err := r.h.GetMyCreditBalance(asCaller("user-a"), &pb.GetMyCreditBalanceReq{})
	if err != nil || bal.GetBalance().GetUserId() != "user-a" {
		t.Fatalf("balance of user-a: %v, %+v", err, bal)
	}
	meter, err := r.h.GetMyUsageMeter(asCaller("user-b"), &pb.GetMyUsageMeterReq{Meter: "api", Period: "2026-10"})
	if err != nil || meter.GetMeter().GetUserId() != "user-b" || meter.GetMeter().GetTotal() != 1 {
		t.Fatalf("meter of user-b: %v, %+v", err, meter)
	}
}

// Before the first grant or report there is no balance or meter row. The
// caller's own wallet and meter then read as zero, not as missing.
func TestGetMyBalanceAndMeter_ZeroBeforeTheFirstApply(t *testing.T) {
	r := newRig(t)
	bal, err := r.h.GetMyCreditBalance(asCaller("user-new"), &pb.GetMyCreditBalanceReq{})
	if err != nil || bal.GetBalance().GetUserId() != "user-new" || bal.GetBalance().GetBalance() != "0" {
		t.Fatalf("balance before any credit: %v, %+v", err, bal)
	}
	meter, err := r.h.GetMyUsageMeter(asCaller("user-new"), &pb.GetMyUsageMeterReq{Meter: "api", Period: "2026-10"})
	if err != nil || meter.GetMeter().GetUserId() != "user-new" || meter.GetMeter().GetMeter() != "api" || meter.GetMeter().GetTotal() != 0 {
		t.Fatalf("meter before any report: %v, %+v", err, meter)
	}
}

// A caller reads their own subscription; another customer's reads as not
// found.
func TestGetMySubscription_OnlyTheOwnersSubscription(t *testing.T) {
	q := &fakeQuery{
		customer:     &pb.Customer{Id: "cust-a", UserId: "user-a"},
		subscription: &pb.Subscription{Id: "sub-1", CustomerId: "cust-a"},
	}
	h := subHandler(q, &fakeMutation{}, &fakeBackend{})
	got, err := h.GetMySubscription(asCaller("user-a"), &pb.GetMySubscriptionReq{Id: "sub-1"})
	if err != nil || got.GetSubscription().GetId() != "sub-1" {
		t.Fatalf("owner read: %v, %+v", err, got)
	}
	q.subscription.CustomerId = "cust-b"
	_, err = h.GetMySubscription(asCaller("user-a"), &pb.GetMySubscriptionReq{Id: "sub-1"})
	wantCode(t, err, codes.NotFound, "another customer's subscription")
}
