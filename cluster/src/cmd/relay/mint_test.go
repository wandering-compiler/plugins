package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Minting is idempotent: the second run prints the same fingerprint, because
// every one printed is pinned somewhere.
func TestMint_KeepsWhatItMade(t *testing.T) {
	dir := t.TempDir()
	var a, b bytes.Buffer
	if err := mint([]string{"--dir", dir, "--name", "relay", "--ca"}, &a); err != nil {
		t.Fatal(err)
	}
	if err := mint([]string{"--dir", dir, "--name", "relay", "--ca"}, &b); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() || !strings.HasPrefix(a.String(), "relay ") {
		t.Fatalf("first %q, second %q — a re-run must keep the identity", a.String(), b.String())
	}
	for _, f := range []string{"relay.crt", "relay.key", "ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestMint_RefusesWithoutDirOrName(t *testing.T) {
	if err := mint([]string{"--name", "x"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}
