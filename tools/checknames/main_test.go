package main

import "testing"

func TestTokensAndHashMatchTheGateForm(t *testing.T) {
	// The list arrives as hash:length of the lowercased name; a token is matched
	// case-insensitively and only as a whole word.
	denied, lengths, err := parseDenied(hash("acme") + ":4")
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	for _, tok := range tokens("Acme rolled out acmes; ACME-ish") {
		if lengths[len(tok)] && denied[hash(tok)] == len(tok) {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (Acme, ACME — not acmes)", hits)
	}
	if _, _, err := parseDenied("nothash:4"); err == nil {
		t.Error("a malformed entry was accepted")
	}
}
