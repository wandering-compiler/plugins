package workerconn

import (
	"os"
	"strings"
)

// The environment a worker reads its pool from. These are the names the
// plugin's deploy block sets on the worker service (plugin.yaml,
// deploy.services[worker].env), so a worker that calls ConfigFromEnv starts
// under a w17 deploy target unchanged, and a hand-written stack that sets the
// same names gets the same worker. One contract: a worker inventing its own
// names starts locally and refuses to start under the generated stage.
//
//	W17_<ACTIVATION>_RELAY_ATTACH        RelayAddress (the relay's attach listener)
//	W17_<ACTIVATION>_RELAY_TUNNEL        TunnelAddress (the relay's tunnel listener)
//	W17_<ACTIVATION>_RELAY_FINGERPRINT   RelayFingerprint
//	W17_<ACTIVATION>_IDENTITY_DIR        IdentityDir
//	W17_<ACTIVATION>_WORKER_NAME         Name
//	W17_<ACTIVATION>_REGISTRATION_CODE   RegistrationCode (not set by the deploy:
//	                                     it issues the certificate directly)
//
// <ACTIVATION> is the activation name upper-cased, every character other
// than a letter or digit an underscore: `browser` → W17_BROWSER_RELAY_ATTACH.
const (
	EnvRelayAttach      = "RELAY_ATTACH"
	EnvRelayTunnel      = "RELAY_TUNNEL"
	EnvRelayFingerprint = "RELAY_FINGERPRINT"
	EnvIdentityDir      = "IDENTITY_DIR"
	EnvWorkerName       = "WORKER_NAME"
	EnvRegistrationCode = "REGISTRATION_CODE"
)

// EnvName is the variable a worker of activation reads for suffix (one of
// the Env* constants): EnvName("browser", EnvRelayAttach) is
// W17_BROWSER_RELAY_ATTACH.
func EnvName(activation, suffix string) string {
	var b strings.Builder
	b.WriteString("W17_")
	for _, r := range activation {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	b.WriteByte('_')
	b.WriteString(suffix)
	return b.String()
}

// ConfigFromEnv fills the connection half of a Config from the environment
// (the names above). What belongs to the machine — Slots, Engines,
// Readiness, DeviceID — is the worker's to set on the result; Run refuses a
// Config that still lacks a required field, naming it.
func ConfigFromEnv(activation string) Config {
	return configFromEnv(activation, os.Getenv)
}

func configFromEnv(activation string, getenv func(string) string) Config {
	get := func(suffix string) string { return strings.TrimSpace(getenv(EnvName(activation, suffix))) }
	return Config{
		RelayAddress:     get(EnvRelayAttach),
		TunnelAddress:    get(EnvRelayTunnel),
		RelayFingerprint: get(EnvRelayFingerprint),
		IdentityDir:      get(EnvIdentityDir),
		Name:             get(EnvWorkerName),
		RegistrationCode: get(EnvRegistrationCode),
	}
}
