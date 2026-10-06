package passwordhash

import (
	"strings"
	"testing"
)

// Test params kept low for fast unit-test runs. Production
// reads OWASP-recommended values from the lock at startup.
func testParams() Params {
	return Params{
		Argon2idMemKiB:  4096, // 4 MiB
		Argon2idIters:   1,
		Argon2idThreads: 1,
		BcryptCost:      4, // bcrypt minimum
		ScryptN:         1024,
		ScryptR:         8,
		ScryptP:         1,
		PBKDF2Iters:     1000,
	}
}

// TestHashVerify_RoundTrip pins that every supported algorithm
// can hash + verify the original plain text. Same shape across
// all four algos.
func TestHashVerify_RoundTrip(t *testing.T) {
	for _, algo := range []Algo{Argon2id, Bcrypt, Scrypt, PBKDF2_SHA256} {
		algo := algo
		t.Run(algo.String(), func(t *testing.T) {
			plain := "correct horse battery staple"
			hash, err := Hash(plain, algo, testParams())
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if hash == plain {
				t.Fatal("Hash returned the plain text unchanged")
			}
			ok, _ := Verify(hash, plain, algo, testParams())
			if !ok {
				t.Errorf("Verify(correct plain) returned false; hash=%q", hash)
			}
			ok, _ = Verify(hash, "wrong password", algo, testParams())
			if ok {
				t.Errorf("Verify(wrong plain) returned true; hash=%q", hash)
			}
		})
	}
}

// TestHash_PrefixesPerAlgo pins the encoded-format prefix for
// every algorithm. The prefix is the wire contract — Verify
// dispatches by reading it; rotation between algos relies on
// it; bumping the prefix is a breaking change for every
// existing project's stored hashes.
func TestHash_PrefixesPerAlgo(t *testing.T) {
	cases := []struct {
		algo   Algo
		prefix string
	}{
		{Argon2id, "$argon2id$"},
		{Bcrypt, "$2"}, // bcrypt uses $2a$, $2b$, $2y$ — any 2X
		{Scrypt, "$scrypt$"},
		{PBKDF2_SHA256, "$pbkdf2-sha256$"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.algo.String(), func(t *testing.T) {
			hash, err := Hash("test123", c.algo, testParams())
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if !strings.HasPrefix(hash, c.prefix) {
				t.Errorf("hash %q missing prefix %q", hash, c.prefix)
			}
		})
	}
}

// TestVerify_AutoDetectsAlgo confirms Verify dispatches by
// reading the stored prefix — calling Verify with a project
// currently configured for argon2id against a bcrypt-encoded
// hash succeeds when the plain matches.
func TestVerify_AutoDetectsAlgo(t *testing.T) {
	// Hash with bcrypt.
	stored, err := Hash("secret", Bcrypt, testParams())
	if err != nil {
		t.Fatalf("Hash bcrypt: %v", err)
	}
	// Verify with project default = argon2id; should still succeed
	// (algo auto-detected from prefix) AND needsRehash=true
	// (default algo is now argon2id; existing hash is bcrypt).
	ok, needsRehash := Verify(stored, "secret", Argon2id, testParams())
	if !ok {
		t.Errorf("Verify failed to auto-detect bcrypt prefix")
	}
	if !needsRehash {
		t.Errorf("Verify should signal needsRehash=true on algo mismatch")
	}
}

// TestVerify_NeedsRehashOnWeakerParams flags hashes whose
// embedded params are weaker than the project's current
// defaults. Rotation flow can then re-hash transparently.
func TestVerify_NeedsRehashOnWeakerParams(t *testing.T) {
	weak := Params{
		Argon2idMemKiB:  1024,
		Argon2idIters:   1,
		Argon2idThreads: 1,
	}
	stored, err := Hash("secret", Argon2id, weak)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// Verify against stronger current params — same algo but
	// the stored params are weaker than current default.
	strong := Params{
		Argon2idMemKiB:  65536,
		Argon2idIters:   3,
		Argon2idThreads: 4,
	}
	ok, needsRehash := Verify(stored, "secret", Argon2id, strong)
	if !ok {
		t.Errorf("Verify rejected matching plain on weaker stored params")
	}
	if !needsRehash {
		t.Errorf("Verify should flag needsRehash on weaker stored params")
	}
}

// TestVerify_NoRehashOnExactMatch confirms needsRehash=false
// when stored algo + params match current.
func TestVerify_NoRehashOnExactMatch(t *testing.T) {
	params := testParams()
	stored, err := Hash("secret", Argon2id, params)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, needsRehash := Verify(stored, "secret", Argon2id, params)
	if !ok {
		t.Errorf("Verify rejected matching plain")
	}
	if needsRehash {
		t.Errorf("Verify should NOT flag needsRehash on exact algo + params match")
	}
}

// TestHash_DifferentSaltPerCall confirms hashing the same
// plain twice produces different encoded outputs (different
// salt). Every modern algo with random salt MUST satisfy this.
func TestHash_DifferentSaltPerCall(t *testing.T) {
	for _, algo := range []Algo{Argon2id, Bcrypt, Scrypt, PBKDF2_SHA256} {
		algo := algo
		t.Run(algo.String(), func(t *testing.T) {
			h1, err := Hash("same-plain", algo, testParams())
			if err != nil {
				t.Fatalf("Hash 1: %v", err)
			}
			h2, err := Hash("same-plain", algo, testParams())
			if err != nil {
				t.Fatalf("Hash 2: %v", err)
			}
			if h1 == h2 {
				t.Errorf("two Hash() calls produced identical output; salt not randomised")
			}
		})
	}
}

// TestHash_RejectsEmptyPlain — empty plain is a misuse (likely
// a "don't change" semantic that should be handled upstream by
// the storage codegen, not arriving here).
func TestHash_RejectsEmptyPlain(t *testing.T) {
	_, err := Hash("", Argon2id, testParams())
	if err == nil {
		t.Error("expected error on empty plain, got nil")
	}
}

// TestHash_RejectsUnknownAlgo — defensive guard.
func TestHash_RejectsUnknownAlgo(t *testing.T) {
	_, err := Hash("secret", AlgoUnknown, testParams())
	if err == nil {
		t.Error("expected error on AlgoUnknown, got nil")
	}
}

// TestVerify_RejectsMalformedHash — verify must fail closed on
// garbage input rather than panic.
func TestVerify_RejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"not a hash",
		"$argon2id$totally-broken",
		"$unknown$v=1$m=4$x$y",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			ok, _ := Verify(c, "anything", Argon2id, testParams())
			if ok {
				t.Errorf("Verify accepted malformed stored hash %q", c)
			}
		})
	}
}

// TestDefaultParams pins the OWASP-2024-recommended defaults.
// Bumping these is a security-meaningful change — drop the
// test if the recommended ceiling actually moves; never silently
// weaken.
func TestDefaultParams(t *testing.T) {
	p := DefaultParams()
	if p.Argon2idMemKiB < 19456 {
		t.Errorf("argon2id memory %d KiB below OWASP minimum 19 MiB", p.Argon2idMemKiB)
	}
	if p.BcryptCost < 10 {
		t.Errorf("bcrypt cost %d below practical minimum 10", p.BcryptCost)
	}
	if p.PBKDF2Iters < 600000 {
		t.Errorf("pbkdf2 iters %d below OWASP 2024 baseline 600k", p.PBKDF2Iters)
	}
}
