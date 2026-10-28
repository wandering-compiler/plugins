package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withProto adds a proto file to a throwaway plugin tree.
func withProto(t *testing.T, dir, body string) {
	t.Helper()
	p := filepath.Join(dir, "proto", "types", "models.proto")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const gatedFieldProto = `syntax = "proto3";
message Membership {
  string org_id = 1;
  string kind   = 2 [(w17.contrib.plugin_feature_field) = "alpha"];
}
message Other {
  string label = 1 [(w17.contrib.plugin_feature_field) = "alpha"];
}
message Third {
  string label = 1;
}
`

// A feature's file calling the getter of a field another feature adds: it
// compiles in the author tree and is an undefined method in the activation
// that enables beta without alpha.
func TestCheck_AGatedFieldsGetterAcrossFeatures(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/alpha.go": "func a(m interface{ GetKind() string }) string { return m.GetKind() }",
		"handlers/beta.go":  "func b(m interface{ GetKind() string }) string { return m.GetKind() }",
	})
	withProto(t, dir, gatedFieldProto)
	err := check(dir)
	if err == nil || !strings.Contains(err.Error(), "calls GetKind, a field only alpha adds") {
		t.Fatalf("err = %v, want beta's call reported", err)
	}
	if strings.Contains(err.Error(), "handlers/alpha.go") {
		t.Errorf("alpha's own file was reported: %v", err)
	}
}

// A getter another message declares ungated cannot be attributed from the
// call site, and is not reported.
func TestCheck_AnAmbiguousGetterIsNotReported(t *testing.T) {
	dir := plugin(t, twoFeatures, map[string]string{
		"handlers/beta.go": "func b(m interface{ GetLabel() string }) string { return m.GetLabel() }",
	})
	withProto(t, dir, gatedFieldProto)
	if err := check(dir); err != nil {
		t.Fatalf("an ambiguous getter was reported: %v", err)
	}
}

func TestGetterOf(t *testing.T) {
	for field, want := range map[string]string{"membership_kind": "GetMembershipKind", "org_id": "GetOrgId", "x": "GetX"} {
		if got := getterOf(field); got != want {
			t.Errorf("getterOf(%q) = %q, want %q", field, got, want)
		}
	}
}
