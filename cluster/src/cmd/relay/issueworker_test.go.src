package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
)

func TestIssueWorker_FromTheRelaysIdentityDir(t *testing.T) {
	relayDir := t.TempDir()
	ca, err := identity.LoadOrCreateCA(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	workerDir := filepath.Join(t.TempDir(), "worker")
	var out bytes.Buffer
	if err := issueWorker([]string{"--identity-dir", relayDir, "--out", workerDir, "--name", "w1"}, &out); err != nil {
		t.Fatalf("issue-worker: %v", err)
	}
	_, leaf, err := identity.LoadWorkerCertificate(workerDir)
	if err != nil {
		t.Fatalf("no worker certificate written: %v", err)
	}
	if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
		t.Fatalf("the worker certificate is not from the relay's CA: %v", err)
	}
	id, _ := identity.PublicKeyID(leaf.PublicKey)
	if !strings.Contains(out.String(), id) {
		t.Fatalf("the output does not name the worker ID %s an operator bans by:\n%s", id, out.String())
	}
}

// Without a CA in the relay's directory nothing is minted: a worker chained to
// a CA no relay uses could never attach.
func TestIssueWorker_RefusesToMintACA(t *testing.T) {
	relayDir := t.TempDir()
	err := issueWorker([]string{"--identity-dir", relayDir, "--out", t.TempDir(), "--name", "w1"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no relay CA in") {
		t.Fatalf("err = %v, want a refusal naming the missing CA", err)
	}
	if _, statErr := os.Stat(filepath.Join(relayDir, "ca.key")); !os.IsNotExist(statErr) {
		t.Fatalf("a CA was minted in the relay directory (stat: %v)", statErr)
	}
}
