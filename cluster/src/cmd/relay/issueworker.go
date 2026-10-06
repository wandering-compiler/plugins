package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
)

// issueWorker is `relay issue-worker`: enrol a worker without a registration
// code, by writing its key and a certificate from this relay's CA into the
// worker's identity directory. Codes are issued from the admin; this is for
// where no admin exists yet — a deployment's first worker, a dev stack, a
// test. It needs the CA itself, which is why only an operator can run it.
func issueWorker(args []string, out io.Writer) error {
	cfg := config{}
	var dir, name string
	var lifetime time.Duration
	fs := flag.NewFlagSet("relay issue-worker", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.caCertPath, "ca-cert", os.Getenv("RELAY_CA_CERT"), "PEM certificate of the relay's worker CA")
	fs.StringVar(&cfg.caKeyPath, "ca-key", os.Getenv("RELAY_CA_KEY"), "PEM private key for --ca-cert")
	fs.StringVar(&cfg.identityDir, "identity-dir", os.Getenv("RELAY_IDENTITY_DIR"),
		"the relay's identity directory holding its CA (dev), instead of --ca-cert/--ca-key")
	fs.StringVar(&dir, "out", "", "the WORKER's identity directory (its W17_CODEGEN_IDENTITY_DIR) — its key is made there, or kept")
	fs.StringVar(&name, "name", "", "a label for logs")
	fs.DurationVar(&lifetime, "lifetime", relayserver.DefaultWorkerCertLifetime,
		"how long the certificate lasts; the worker renews it from then on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(dir) == "" {
		return errors.New("issue-worker: --out names the worker's identity directory")
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("issue-worker: --name labels the worker in logs")
	}
	if strings.TrimSpace(cfg.identityDir) != "" {
		// relayCA would MINT a CA where none is, and a worker chained to a
		// CA no relay uses would never attach: the relay makes its CA, this
		// only reads it.
		if _, err := os.Stat(filepath.Join(cfg.identityDir, "ca.crt")); err != nil {
			return fmt.Errorf("issue-worker: no relay CA in %s (start the relay once first): %w", cfg.identityDir, err)
		}
	}
	ca, err := relayCA(cfg)
	if err != nil {
		return err
	}
	id, notAfter, err := ca.IssueWorkerIdentity(dir, name, lifetime)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "worker %s enrolled in %s\n  id %s (what a ban names)\n  certificate valid until %s; the worker renews it\n",
		name, dir, id, notAfter.UTC().Format(time.RFC3339))
	return err
}
