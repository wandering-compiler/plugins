package workerconn

import (
	"os"
	"regexp"
	"testing"
)

func TestEnvName(t *testing.T) {
	for in, want := range map[string]string{
		"browser":     "W17_BROWSER_RELAY_ATTACH",
		"codegen":     "W17_CODEGEN_RELAY_ATTACH",
		"pool-2":      "W17_POOL_2_RELAY_ATTACH",
		"headless_ch": "W17_HEADLESS_CH_RELAY_ATTACH",
	} {
		if got := EnvName(in, EnvRelayAttach); got != want {
			t.Errorf("EnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"W17_BROWSER_RELAY_ATTACH":      "relay:13446",
		"W17_BROWSER_RELAY_TUNNEL":      "relay:13445",
		"W17_BROWSER_RELAY_FINGERPRINT": " abc ",
		"W17_BROWSER_IDENTITY_DIR":      "/var/lib/worker",
		"W17_BROWSER_WORKER_NAME":       "prod-worker-1",
		"W17_CODEGEN_RELAY_ATTACH":      "other:1",
	}
	cfg := configFromEnv("browser", func(k string) string { return env[k] })
	if cfg.RelayAddress != "relay:13446" || cfg.TunnelAddress != "relay:13445" ||
		cfg.RelayFingerprint != "abc" || cfg.IdentityDir != "/var/lib/worker" ||
		cfg.Name != "prod-worker-1" || cfg.RegistrationCode != "" {
		t.Fatalf("configFromEnv = %+v", cfg)
	}
}

// The names ConfigFromEnv reads are the ones the deploy block sets on the
// worker service: the two drifting apart is the bug this file exists to
// prevent.
func TestConfigFromEnvMatchesDeployBlock(t *testing.T) {
	raw, err := os.ReadFile("../../../plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, m := range regexp.MustCompile(`"W17_\{ACTIVATION\}_([A-Z_]+)"`).FindAllStringSubmatch(string(raw), -1) {
		set[m[1]] = true
	}
	if len(set) == 0 {
		t.Fatal("plugin.yaml's worker service sets no W17_{ACTIVATION}_* variable")
	}
	read := map[string]bool{EnvRelayAttach: true, EnvRelayTunnel: true, EnvRelayFingerprint: true, EnvIdentityDir: true, EnvWorkerName: true}
	for s := range set {
		if !read[s] {
			t.Errorf("the deploy block sets W17_{ACTIVATION}_%s, which ConfigFromEnv does not read", s)
		}
	}
	for s := range read {
		if !set[s] {
			t.Errorf("ConfigFromEnv reads W17_{ACTIVATION}_%s, which the deploy block does not set", s)
		}
	}
}
