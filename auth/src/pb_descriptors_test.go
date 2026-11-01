package auth_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The pb descriptors must LOAD, not merely compile.
//
// A .pb.go carries its FileDescriptorProto as a serialized byte string with
// LENGTH PREFIXES, so text-editing anything inside it — an import path in
// go_package, for instance — leaves every following offset wrong and the
// package panics at init with a slice-bounds error. `go build` says nothing
// about that; only loading does.
//
// Renaming a module by text substitution rewrites the path inside those bytes,
// and the corruption surfaces as an unrelated-looking panic deep in protobuf's
// descriptor parser, in a test for something else entirely. The pb is
// generated (`w17ctl plugin gen`), so this lives beside the plugin's own code
// rather than in gen/, which the generator owns.
func TestDescriptorsLoad(t *testing.T) {
	for name, fd := range map[string]interface{ Path() string }{
		"types/models":          pb.File_types_models_proto,
		"business/auth_service": pb.File_business_auth_service_proto,
		"events/auth_events":    pb.File_events_auth_events_proto,
		"queries/auth_query":    pb.File_queries_auth_query_proto,
	} {
		if fd == nil {
			t.Errorf("%s: descriptor did not initialise", name)
			continue
		}
		if fd.Path() == "" {
			t.Errorf("%s: descriptor has no path", name)
		}
	}
}

// ResolveUser answers any user's envelope to its caller, so it must carry
// (w17.contrib.plugin_internal_rpc): that option, not the presets leaving it
// out, is what makes codegen refuse it on every surface a project could name
// it on. Read as the raw option field, since the SDK this module builds
// against may predate the option.
func TestResolveUser_IsMarkedInternal(t *testing.T) {
	assertInternalRPC(t, "ResolveUser")
}

// WithdrawMarketingConsent names the user whose consent it withdraws, so it
// is internal too: only the domain's own code may call it.
func TestWithdrawMarketingConsent_IsMarkedInternal(t *testing.T) {
	assertInternalRPC(t, "WithdrawMarketingConsent")
}

func assertInternalRPC(t *testing.T, rpc string) {
	t.Helper()
	const pluginInternalRPC = 51028
	m := pb.File_business_auth_service_proto.Services().ByName("AuthService").Methods().ByName(protoreflect.Name(rpc))
	if m == nil {
		t.Fatalf("AuthService.%s is not in the descriptor", rpc)
	}
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok {
		t.Fatalf("%s's options are %T", rpc, m.Options())
	}
	raw, err := proto.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatal("malformed options")
		}
		raw = raw[n:]
		if num == pluginInternalRPC && typ == protowire.VarintType {
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 || v != 1 {
				t.Fatalf("plugin_internal_rpc = %d, want true", v)
			}
			return
		}
		n = protowire.ConsumeFieldValue(num, typ, raw)
		if n < 0 {
			t.Fatal("malformed options")
		}
		raw = raw[n:]
	}
	t.Fatalf("%s does not carry (w17.contrib.plugin_internal_rpc) = true: a project's own refs could put it on a surface", rpc)
}

// Every event that carries a credential for a person maps its sealed_* field
// from the request beside the clear one: without the mapping the sealed value
// never reaches the mailer, and the event goes out with neither.
func TestSecretEvents_CarryTheSealedField(t *testing.T) {
	methods := pb.File_mutations_auth_mutation_proto.Services().ByName("AuthMutation").Methods()
	for rpc, field := range map[string]string{
		"CreatePasswordResetToken":     "token",
		"CreateEmailVerificationToken": "token",
		"CreatePendingSignUp":          "code",
		"CreateMfaChallenge":           "code",
		"SetStepUpCode":                "code",
	} {
		m := methods.ByName(protoreflect.Name(rpc))
		if m == nil {
			t.Errorf("AuthMutation.%s does not exist", rpc)
			continue
		}
		emit, _ := proto.GetExtension(m.Options(), w17pb.E_EventEmit).(*w17pb.EmitConfig)
		mapped := map[string]string{}
		for _, f := range emit.GetPayload().GetFields() {
			mapped[f.GetKey()] = f.GetValue()
		}
		if mapped["sealed_"+field] != "$request.sealed_"+field {
			t.Errorf("%s → %s maps sealed_%s from %q, want $request.sealed_%s", rpc, emit.GetEvent(), field, mapped["sealed_"+field], field)
		}
		if mapped[field] != "$request."+field {
			t.Errorf("%s → %s lost the clear %s mapping (dev without a recipient)", rpc, emit.GetEvent(), field)
		}
	}
}
