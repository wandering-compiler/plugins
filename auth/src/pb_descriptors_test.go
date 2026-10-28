package auth_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

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
	const pluginInternalRPC = 51028
	m := pb.File_business_auth_service_proto.Services().ByName("AuthService").Methods().ByName("ResolveUser")
	if m == nil {
		t.Fatal("AuthService.ResolveUser is not in the descriptor")
	}
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok {
		t.Fatalf("ResolveUser's options are %T", m.Options())
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
	t.Fatal("ResolveUser does not carry (w17.contrib.plugin_internal_rpc) = true: a project's own refs could put it on a surface")
}
