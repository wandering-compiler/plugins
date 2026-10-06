package passwordhash

import (
	"errors"
	"testing"
)

func testSettings() Settings {
	return Settings{Algo: Argon2id, Params: testParams()}
}

// TestSettings_DefaultSettings pins the OWASP-default bundle —
// the same defaults the docs promise.
func TestSettings_DefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.Algo != Argon2id {
		t.Errorf("DefaultSettings.Algo = %v, want Argon2id", s.Algo)
	}
	if s.Params.Argon2idMemKiB != DefaultParams().Argon2idMemKiB {
		t.Errorf("DefaultSettings.Params not the OWASP defaults")
	}
}

// TestSettings_HashVerify_RoundTrip pins that the methods delegate
// to the package-level functions for the typical happy path.
func TestSettings_HashVerify_RoundTrip(t *testing.T) {
	s := testSettings()
	hash, err := s.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Settings.Hash: %v", err)
	}
	ok, needsRehash := s.Verify(hash, "correct horse battery staple")
	if !ok {
		t.Errorf("Settings.Verify rejected matching plain")
	}
	if needsRehash {
		t.Errorf("Settings.Verify flagged needsRehash on exact match")
	}
}

// TestSettings_VerifyAndRotate_NoRotationOnExactMatch — happy
// login path, no rotation needed, updateFn must not be called.
func TestSettings_VerifyAndRotate_NoRotationOnExactMatch(t *testing.T) {
	s := testSettings()
	stored, err := s.Hash("secret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	called := false
	ok, rotated, err := s.VerifyAndRotate(stored, "secret", func(string) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("VerifyAndRotate returned err on exact match: %v", err)
	}
	if !ok {
		t.Errorf("VerifyAndRotate ok=false on matching plain")
	}
	if rotated {
		t.Errorf("VerifyAndRotate rotated=true on exact algo+params match")
	}
	if called {
		t.Errorf("VerifyAndRotate called updateFn when no rotation was needed")
	}
}

// TestSettings_VerifyAndRotate_RotatesOnAlgoMismatch — stored
// hash uses bcrypt, current settings use argon2id; successful
// verify must trigger a rehash + updateFn call with a fresh
// argon2id-prefixed hash.
func TestSettings_VerifyAndRotate_RotatesOnAlgoMismatch(t *testing.T) {
	bcryptHash, err := Hash("secret", Bcrypt, testParams())
	if err != nil {
		t.Fatalf("Hash bcrypt: %v", err)
	}
	current := testSettings() // argon2id
	var captured string
	ok, rotated, err := current.VerifyAndRotate(bcryptHash, "secret", func(newHash string) error {
		captured = newHash
		return nil
	})
	if err != nil {
		t.Errorf("VerifyAndRotate err: %v", err)
	}
	if !ok {
		t.Errorf("VerifyAndRotate failed to verify bcrypt-stored credential under argon2id current")
	}
	if !rotated {
		t.Errorf("VerifyAndRotate rotated=false on algo mismatch")
	}
	if captured == "" {
		t.Fatalf("VerifyAndRotate didn't pass new hash to updateFn")
	}
	if captured[:10] != "$argon2id$" {
		t.Errorf("rotated hash %q not argon2id-prefixed", captured)
	}
}

// TestSettings_VerifyAndRotate_PreservesAuthOnUpdateError —
// verified credentials remain verified (ok=true) even when the
// update callback fails. The error is returned for observability
// but the caller should still grant access.
func TestSettings_VerifyAndRotate_PreservesAuthOnUpdateError(t *testing.T) {
	bcryptHash, err := Hash("secret", Bcrypt, testParams())
	if err != nil {
		t.Fatalf("Hash bcrypt: %v", err)
	}
	current := testSettings()
	updateErr := errors.New("storage unreachable")
	ok, rotated, err := current.VerifyAndRotate(bcryptHash, "secret", func(string) error {
		return updateErr
	})
	if !errors.Is(err, updateErr) {
		t.Errorf("VerifyAndRotate err = %v, want updateErr", err)
	}
	if !ok {
		t.Errorf("VerifyAndRotate ok=false when only the rotation persist failed")
	}
	if rotated {
		t.Errorf("VerifyAndRotate rotated=true when updateFn errored")
	}
}

// TestSettings_VerifyAndRotate_RejectsBadCredential — wrong
// plain must return ok=false and never call updateFn.
func TestSettings_VerifyAndRotate_RejectsBadCredential(t *testing.T) {
	s := testSettings()
	stored, err := s.Hash("secret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	called := false
	ok, rotated, err := s.VerifyAndRotate(stored, "wrong-password", func(string) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("VerifyAndRotate err on wrong plain: %v", err)
	}
	if ok {
		t.Errorf("VerifyAndRotate ok=true on wrong plain")
	}
	if rotated {
		t.Errorf("VerifyAndRotate rotated=true on wrong plain")
	}
	if called {
		t.Errorf("VerifyAndRotate called updateFn on wrong plain")
	}
}

// TestSettings_VerifyAndRotate_NilUpdateFn — passing nil
// updateFn degenerates to a Verify; rotated=false even when the
// stored hash would otherwise need rotation. Useful for read-only
// checks where the caller can't persist (e.g. dry-run probes).
func TestSettings_VerifyAndRotate_NilUpdateFn(t *testing.T) {
	bcryptHash, err := Hash("secret", Bcrypt, testParams())
	if err != nil {
		t.Fatalf("Hash bcrypt: %v", err)
	}
	current := testSettings()
	ok, rotated, err := current.VerifyAndRotate(bcryptHash, "secret", nil)
	if err != nil {
		t.Errorf("VerifyAndRotate err with nil updateFn: %v", err)
	}
	if !ok {
		t.Errorf("VerifyAndRotate ok=false on matching plain with nil updateFn")
	}
	if rotated {
		t.Errorf("VerifyAndRotate rotated=true with nil updateFn")
	}
}
