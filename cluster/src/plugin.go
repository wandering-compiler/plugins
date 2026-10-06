// Package cluster is the plugin entry point the bundle calls at boot.
package cluster

import (
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/platform/plugins/cluster/gen"
	"github.com/wandering-compiler/platform/plugins/cluster/handlers"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaydial"
)

// RegisterPlugin wires the control plane's half of the cluster.
//
// The signature is fixed by the v4 bundle codegen and is checked by nothing in
// this module — see the warning in gen/interfaces.go. Three arguments.
func RegisterPlugin(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if cfg == nil {
		cfg = &gen.EnvConfig{}
	}
	if registry == nil || clients == nil {
		return fmt.Errorf("cluster: RegisterPlugin needs both a registry and a client set")
	}

	// Loaded at BOOT, not at the first schedule. A control plane with no
	// client identity cannot reach any relay, so every call it accepts is one
	// it will fail — better to refuse to start than to look healthy and
	// discover it when somebody is waiting for a slot.
	dialCfg, err := loadIdentity(cfg)
	if err != nil {
		return err
	}

	// The env contract says this bounds opening ONE management connection, and
	// it has to be applied here or it is a promise nothing keeps: grpc.NewClient
	// is lazy, so an unreachable relay would not fail at dial — it would hold
	// ScheduleTask until the CALLER's deadline, which is the opposite of
	// "skipped quickly enough that scheduling falls through to a healthy one".
	dialTimeout := time.Duration(cfg.DialTimeoutSeconds) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	registry.RegisterClusterServiceServer(&handlers.ClusterServiceHandler{
		Relays:      handlers.NewRelayStore(clients.RelayQuery(), clients.RelayMutation()),
		Workers:     handlers.NewWorkerStore(clients.WorkerQuery(), clients.WorkerMutation()),
		DialTimeout: dialTimeout,
		Dial: func(target, fingerprint string) (*grpc.ClientConn, error) {
			return relaydial.Dial(dialCfg, target, fingerprint)
		},
	})
	return nil
}

func loadIdentity(cfg *gen.EnvConfig) (relaydial.Config, error) {
	certPath := strings.TrimSpace(cfg.ClientCertPath)
	keyPath := strings.TrimSpace(cfg.ClientKeyPath)
	if certPath == "" || keyPath == "" {
		return relaydial.Config{}, fmt.Errorf(
			"cluster: client_cert_path and client_key_path are both required — " +
				"the control plane dials out to relays and has no other way to identify itself")
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return relaydial.Config{}, fmt.Errorf("cluster: reading client_cert_path: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return relaydial.Config{}, fmt.Errorf("cluster: reading client_key_path: %w", err)
	}
	return relaydial.Config{ClientCertPEM: cert, ClientKeyPEM: key}, nil
}
