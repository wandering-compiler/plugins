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
	contains := func(line, want string) bool {
		for _, tok := range tokens(line) {
			if tok == want {
				return true
			}
		}
		return false
	}
	for line, want := range map[string]string{
		"newAcmeClient()":   "acme",     // camelCase
		"ACMEClient":        "acme",     // acronym then word
		"acme-corp ltd":     "acmecorp", // a hyphenated name, joined
		"acme_corp":         "acmecorp",
		"see Acme Corp now": "acmecorp", // two words
	} {
		if !contains(line, want) {
			t.Errorf("tokens(%q) does not reach %q: %v", line, want, tokens(line))
		}
	}
	if isBinary([]byte("plain text")) || !isBinary([]byte("a\x00b")) {
		t.Error("isBinary")
	}
	if _, _, err := parseDenied("nothash:4"); err == nil {
		t.Error("a malformed entry was accepted")
	}
}
