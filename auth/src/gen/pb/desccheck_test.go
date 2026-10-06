package pb

import "testing"

// The descriptors must LOAD, not merely compile.
//
// A .pb.go carries its FileDescriptorProto as a serialized byte string with
// LENGTH PREFIXES, so text-editing anything inside it — an import path in
// go_package, for instance — leaves every following offset wrong and the
// package panics at init with a slice-bounds error. `go build` says nothing
// about that; only loading does.
//
// Written after exactly that: renaming the module by text substitution
// rewrote the path inside these bytes, and the corruption surfaced as an
// unrelated-looking panic deep in protobuf's descriptor parser, in a test for
// something else entirely.
func TestDescriptorsLoad(t *testing.T) {
	for name, fd := range map[string]interface{ Path() string }{
		"types/models":          File_types_models_proto,
		"business/auth_service": File_business_auth_service_proto,
		"events/auth_events":    File_events_auth_events_proto,
		"queries/auth_query":    File_queries_auth_query_proto,
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
