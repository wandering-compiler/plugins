package payment

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// Every (w17.event_emit) payload, read from the generated descriptors (the
// options the codegen reads), maps onto its event: each key names an event
// field, each `$request.*` / `$response.*` source resolves to a field of the
// same type (the same enum, the same message), and every event field is
// mapped — an unmapped one goes out zero, which for an enum reads as
// STATUS_UNSPECIFIED.
func TestEventEmitPayloads_MapEveryEventFieldFromASourceOfItsType(t *testing.T) {
	methods := pb.File_mutations_payment_mutation_proto.Services().ByName("PaymentMutation").Methods()
	emits := 0
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		emit, _ := proto.GetExtension(m.Options(), w17pb.E_EventEmit).(*w17pb.EmitConfig)
		if emit == nil || emit.GetEvent() == "" {
			continue
		}
		emits++
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName("w17.contrib.payment." + emit.GetEvent()))
		if err != nil {
			t.Errorf("%s emits %s: %v", m.Name(), emit.GetEvent(), err)
			continue
		}
		event := d.(protoreflect.MessageDescriptor)
		mapped := map[protoreflect.Name]bool{}
		for _, f := range emit.GetPayload().GetFields() {
			ef := event.Fields().ByName(protoreflect.Name(f.GetKey()))
			if ef == nil {
				t.Errorf("%s → %s: key %q is not an event field", m.Name(), event.Name(), f.GetKey())
				continue
			}
			mapped[ef.Name()] = true
			src, err := resolveSource(m, f.GetValue())
			if err != nil {
				t.Errorf("%s → %s.%s: %v", m.Name(), event.Name(), ef.Name(), err)
				continue
			}
			if got, want := typeName(src), typeName(ef); got != want {
				t.Errorf("%s → %s.%s: source %s is %s, the event field is %s", m.Name(), event.Name(), ef.Name(), f.GetValue(), got, want)
			}
		}
		for j := 0; j < event.Fields().Len(); j++ {
			if ef := event.Fields().Get(j); !mapped[ef.Name()] {
				t.Errorf("%s → %s.%s: not mapped by the payload — it is always zero", m.Name(), event.Name(), ef.Name())
			}
		}
	}
	if emits == 0 {
		t.Fatal("no (w17.event_emit) found on PaymentMutation — the test checked nothing")
	}
}

// SubscriptionStarted says what state the subscription was created in. Stripe
// creates it INCOMPLETE by default (payment_behavior allow_incomplete) until
// the first invoice is paid; without the status, a subscriber granting
// entitlements on SubscriptionStarted granted them to a subscription nobody
// had paid for.
func TestSubscriptionStarted_CarriesTheCreatedStatus(t *testing.T) {
	event := (&pb.SubscriptionStarted{}).ProtoReflect().Descriptor()
	f := event.Fields().ByName("status")
	if f == nil || f.Enum() == nil || f.Enum().FullName() != (pb.Subscription_STATUS_UNSPECIFIED).Descriptor().FullName() {
		t.Fatalf("SubscriptionStarted.status = %v, want a Subscription.Status field", f)
	}
	m := pb.File_mutations_payment_mutation_proto.Services().ByName("PaymentMutation").Methods().ByName("CreateSubscription")
	emit, _ := proto.GetExtension(m.Options(), w17pb.E_EventEmit).(*w17pb.EmitConfig)
	for _, pf := range emit.GetPayload().GetFields() {
		if pf.GetKey() == "status" {
			if pf.GetValue() != "$response.subscription.status" {
				t.Errorf("SubscriptionStarted.status maps %q, want $response.subscription.status", pf.GetValue())
			}
			return
		}
	}
	t.Error("CreateSubscription's SubscriptionStarted payload does not map status")
}

// resolveSource walks a `$request.a.b` / `$response.a.b` payload source to
// the field it names.
func resolveSource(m protoreflect.MethodDescriptor, value string) (protoreflect.FieldDescriptor, error) {
	var msg protoreflect.MessageDescriptor
	var path string
	switch {
	case strings.HasPrefix(value, "$request."):
		msg, path = m.Input(), strings.TrimPrefix(value, "$request.")
	case strings.HasPrefix(value, "$response."):
		msg, path = m.Output(), strings.TrimPrefix(value, "$response.")
	default:
		return nil, &sourceErr{value, "not a $request / $response path"}
	}
	var f protoreflect.FieldDescriptor
	for _, seg := range strings.Split(path, ".") {
		if msg == nil {
			return nil, &sourceErr{value, "walks past a scalar"}
		}
		f = msg.Fields().ByName(protoreflect.Name(seg))
		if f == nil {
			return nil, &sourceErr{value, "no field " + seg + " in " + string(msg.FullName())}
		}
		msg = f.Message()
	}
	return f, nil
}

type sourceErr struct{ value, why string }

func (e *sourceErr) Error() string { return "source " + e.value + ": " + e.why }

func typeName(f protoreflect.FieldDescriptor) string {
	switch {
	case f.Enum() != nil:
		return "enum " + string(f.Enum().FullName())
	case f.Message() != nil:
		return "message " + string(f.Message().FullName())
	}
	return f.Kind().String()
}
