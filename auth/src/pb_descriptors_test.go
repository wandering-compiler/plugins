package auth_test

import (
	"testing"

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
