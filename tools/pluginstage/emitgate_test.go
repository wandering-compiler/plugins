package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// emitPlugin writes a plugin whose service M has one rpc per (name, feature)
// pair, each emitting event Changed; tier is the emit option's name.
func emitPlugin(t *testing.T, tier string, rpcs ...[2]string) string {
	t.Helper()
	dir := t.TempDir()
	var svc strings.Builder
	svc.WriteString("service M {\n")
	for _, r := range rpcs {
		svc.WriteString("  rpc " + r[0] + "(Req) returns (Resp) {\n")
		if r[1] != "" {
			svc.WriteString(`    option (w17.contrib.plugin_feature_rpc) = "` + r[1] + `";` + "\n")
		}
		svc.WriteString("    // option (w17.event_emit) = { event: \"Commented\" };\n")
		svc.WriteString("    option (w17." + tier + ") = {\n      event: \"Changed\"\n      payload: { fields: [] }\n    };\n  }\n")
	}
	svc.WriteString("}\n")
	p := filepath.Join(dir, "proto/mutations/m.proto")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(svc.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The shape auth's MarketingConsentChanged shipped in: two rpcs of one
// feature emit the same event, and every activation with the feature fails.
func TestEmit_TwoSitesOfOneFeatureAreReported(t *testing.T) {
	err := checkEmitSites(emitPlugin(t, "event_emit", [2]string{"Set", "consent"}, [2]string{"Withdraw", "consent"}), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "event Changed") ||
		!strings.Contains(err.Error(), "M.Set") || !strings.Contains(err.Error(), "M.Withdraw") {
		t.Fatalf("err = %v, want both sites of Changed reported", err)
	}
}

// The compiler's rule spans both tiers: a gateway-tier site and a server-tier
// one of the same event collide too.
func TestEmit_GatewayTierCounts(t *testing.T) {
	dir := emitPlugin(t, "event_emit_gateway", [2]string{"A", ""}, [2]string{"B", "x"})
	if err := checkEmitSites(dir, nil, nil); err == nil || !strings.Contains(err.Error(), "event_emit_gateway") {
		t.Fatalf("err = %v, want the gateway-tier sites reported", err)
	}
}

// Sites no activation stages together do not collide: conflicting features,
// or a feature that requires one its rpc's sibling conflicts with.
func TestEmit_SitesNeverStagedTogetherPass(t *testing.T) {
	conflicts := map[[2]string]bool{{"a", "b"}: true, {"b", "a"}: true}
	if err := checkEmitSites(emitPlugin(t, "event_emit", [2]string{"A", "a"}, [2]string{"B", "b"}), nil, conflicts); err != nil {
		t.Errorf("conflicting features: %v", err)
	}
	requires := map[string][]string{"c": {"a"}}
	if err := checkEmitSites(emitPlugin(t, "event_emit", [2]string{"B", "b"}, [2]string{"C", "c"}), requires, conflicts); err != nil {
		t.Errorf("c requires a, which conflicts with b: %v", err)
	}
	if err := checkEmitSites(emitPlugin(t, "event_emit", [2]string{"Only", "a"}), nil, nil); err != nil {
		t.Errorf("one site: %v", err)
	}
}

// Every plugin in this repository passes — auth's MarketingConsentChanged
// included, now that it has one emit site.
func TestEmit_RepositoryPlugins(t *testing.T) {
	manifests, _ := filepath.Glob("../../*/plugin.yaml")
	if len(manifests) == 0 {
		t.Skip("no plugins next to tools/")
	}
	for _, m := range manifests {
		if err := check(filepath.Dir(m)); err != nil && strings.Contains(err.Error(), "more than one emit site") {
			t.Errorf("%s: %v", filepath.Dir(m), err)
		}
	}
}
