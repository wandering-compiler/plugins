package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
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

// A worker the deploy issues into a new state directory is a new key, so a
// ban on the worker it replaces names someone else and does not carry over.
// Issued again into the SAME directory it keeps its key, and so its ban.
func TestIssueWorker_ANewWorkerIsANewIdentityAndEscapesNoBan(t *testing.T) {
	relayDir := t.TempDir()
	if _, err := identity.LoadOrCreateCA(relayDir); err != nil {
		t.Fatal(err)
	}
	issue := func(dir string) string {
		t.Helper()
		if err := issueWorker([]string{"--identity-dir", relayDir, "--out", dir, "--name", "prod-worker-1"}, &bytes.Buffer{}); err != nil {
			t.Fatalf("issue-worker: %v", err)
		}
		_, leaf, err := identity.LoadWorkerCertificate(dir)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.PublicKeyID(leaf.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldDir := filepath.Join(t.TempDir(), "worker")
	old := issue(oldDir)
	bans := workeradmit.New()
	bans.SetBanned([]string{old})

	replacement := issue(filepath.Join(t.TempDir(), "worker"))
	if replacement == old {
		t.Fatalf("a worker issued into a new directory got the old key %s", old)
	}
	if !bans.Admitted(replacement) {
		t.Errorf("the ban on %s carried to the new worker %s", old, replacement)
	}
	if again := issue(oldDir); again != old || bans.Admitted(again) {
		t.Errorf("re-issued into its own directory: id %s (was %s), admitted %v — want the same banned identity", again, old, bans.Admitted(again))
	}
}
