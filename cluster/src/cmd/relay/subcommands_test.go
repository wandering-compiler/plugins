package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
)

// The production shape of issue-worker: the CA comes from mounted secrets,
// not from a dev identity directory, and the worker it enrols chains to it.
func TestIssueWorker_FromAMountedCA(t *testing.T) {
	keys := t.TempDir()
	ca, err := identity.LoadOrCreateCA(keys)
	if err != nil {
		t.Fatal(err)
	}
	workerDir := filepath.Join(t.TempDir(), "worker")
	var out bytes.Buffer
	err = issueWorker([]string{
		"--ca-cert", filepath.Join(keys, "ca.crt"), "--ca-key", filepath.Join(keys, "ca.key"),
		"--out", workerDir, "--name", "acme-1", "--lifetime", "2h",
	}, &out)
	if err != nil {
		t.Fatalf("issue-worker: %v", err)
	}
	_, leaf, err := identity.LoadWorkerCertificate(workerDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Verify(leaf, time.Now()); err != nil {
		t.Errorf("the worker does not chain to the mounted CA: %v", err)
	}
	if life := leaf.NotAfter.Sub(time.Now()); life > 2*time.Hour || life < time.Hour {
		t.Errorf("certificate valid for %s, want the --lifetime of 2h", life)
	}
	if !strings.Contains(out.String(), "acme-1") || !strings.Contains(out.String(), workerDir) {
		t.Errorf("the output does not say which worker went where:\n%s", out.String())
	}
}

// Each way issue-worker can be asked wrongly is refused before anything is
// written — in particular no certificate lands in the worker's directory.
func TestIssueWorker_Refusals(t *testing.T) {
	keys := t.TempDir()
	if _, err := identity.LoadOrCreateCA(keys); err != nil {
		t.Fatal(err)
	}
	caCrt, caKey := filepath.Join(keys, "ca.crt"), filepath.Join(keys, "ca.key")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no --out", []string{"--identity-dir", keys, "--name", "w"}, "--out"},
		{"no --name", []string{"--identity-dir", keys, "--out", "OUT"}, "--name"},
		{"no CA at all", []string{"--out", "OUT", "--name", "w"}, "no worker CA"},
		{"half a mounted CA", []string{"--ca-cert", caCrt, "--out", "OUT", "--name", "w"}, "go together"},
		{"two CAs", []string{"--identity-dir", keys, "--ca-cert", caCrt, "--ca-key", caKey, "--out", "OUT", "--name", "w"}, "two CAs"},
		{"a non-positive lifetime", []string{"--identity-dir", keys, "--out", "OUT", "--name", "w", "--lifetime", "0s"}, "lifetime"},
		{"an unknown flag", []string{"--identity-dir", keys, "--out", "OUT", "--name", "w", "--days", "3"}, "days"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "worker")
			args := make([]string, len(tc.args))
			for i, a := range tc.args {
				if a == "OUT" {
					a = out
				}
				args[i] = a
			}
			err := issueWorker(args, &bytes.Buffer{})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(out, "worker.crt")); !os.IsNotExist(err) {
				t.Errorf("a refused issue-worker still wrote a certificate (stat: %v)", err)
			}
		})
	}
}

// mint refuses what it cannot do rather than printing a fingerprint nobody can
// use: a directory it cannot write, an unknown flag, a half-written CA beside
// the identity.
func TestMint_Refusals(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mint([]string{"--dir", file, "--name", "relay"}, &bytes.Buffer{}); err == nil {
		t.Error("mint into a path that is a file succeeded")
	}
	if err := mint([]string{"--dir", t.TempDir(), "--name", "relay", "--force"}, &bytes.Buffer{}); err == nil {
		t.Error("an unknown flag was accepted")
	}
	half := t.TempDir()
	if err := os.WriteFile(filepath.Join(half, "ca.crt"), []byte("left over"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := mint([]string{"--dir", half, "--name", "relay", "--ca"}, &out)
	if err == nil {
		t.Fatal("mint --ca over a half-written CA succeeded")
	}
	if _, statErr := os.Stat(filepath.Join(half, "ca.key")); !os.IsNotExist(statErr) {
		t.Errorf("a new CA key was minted over the half-written one (stat: %v)", statErr)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// The fingerprint IS mint's output — an operator pastes it into a row. A run
// that could not print it reports that instead of exiting 0 with nothing shown.
func TestMint_AnUnprintableFingerprintIsAnError(t *testing.T) {
	if err := mint([]string{"--dir", t.TempDir(), "--name", "relay", "--ca"}, brokenWriter{}); err == nil {
		t.Fatal("mint succeeded although its output could not be written")
	}
	if err := issueWorker([]string{"--identity-dir", mintedCA(t), "--out", t.TempDir(), "--name", "w"}, brokenWriter{}); err == nil {
		t.Fatal("issue-worker succeeded although its output could not be written")
	}
}

func mintedCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := identity.LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// run dispatches on the first word: the two subcommands never start a relay,
// --help is not a failure, and anything else is a relay configuration.
func TestRun_DispatchesSubcommands(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	stdout := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Stdout = stdout; _ = devnull.Close() })
	os.Stdout = devnull // mint and issue-worker print to stdout

	dir := t.TempDir()
	os.Args = []string{"relay", "mint", "--dir", dir, "--name", "console"}
	if err := run(); err != nil {
		t.Fatalf("relay mint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "console.crt")); err != nil {
		t.Errorf("relay mint did not mint: %v", err)
	}

	os.Args = []string{"relay", "mint", "--dir", dir, "--name", "relay", "--ca"}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	workerDir := filepath.Join(t.TempDir(), "w")
	os.Args = []string{"relay", "issue-worker", "--identity-dir", dir, "--out", workerDir, "--name", "w"}
	if err := run(); err != nil {
		t.Fatalf("relay issue-worker: %v", err)
	}
	if _, _, err := identity.LoadWorkerCertificate(workerDir); err != nil {
		t.Errorf("relay issue-worker did not enrol: %v", err)
	}

	stderr := os.Stderr
	t.Cleanup(func() { os.Stderr = stderr })
	os.Stderr = devnull // the usage text
	os.Args = []string{"relay", "--help"}
	if err := run(); err != nil {
		t.Errorf("relay --help: %v, want a clean exit", err)
	}
	os.Args = []string{"relay", "issueworker", "--out", workerDir}
	if err := run(); err == nil || !strings.Contains(err.Error(), "issueworker") {
		t.Errorf("a misspelt subcommand: %v, want a refusal naming it", err)
	}
}
