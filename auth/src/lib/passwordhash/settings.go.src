package passwordhash

// Settings bundles the algorithm + tuning for a project's
// password hashing. The typical consumer wiring is:
//
//	// at startup
//	s := passwordhash.FromLock(lock.GetPasswordSettings())
//
//	// at registration
//	hash, _ := s.Hash(plaintext)
//
//	// at login
//	ok, rotated, err := s.VerifyAndRotate(stored, plain, func(newHash string) error {
//	    return storage.UpdatePasswordHash(ctx, userID, newHash)
//	})
//
// Passing the bundled Settings keeps the algo + params at one
// call site instead of threading two arguments through every
// hash / verify call.
type Settings struct {
	Algo   Algo
	Params Params
}

// DefaultSettings returns argon2id + OWASP-2024 defaults — the
// fallback every project gets when the lock omits the password
// block.
func DefaultSettings() Settings {
	return Settings{Algo: Argon2id, Params: DefaultParams()}
}

// Hash hashes plain using the bundled algorithm + params.
// Equivalent to passwordhash.Hash(plain, s.Algo, s.Params).
func (s Settings) Hash(plain string) (string, error) {
	return Hash(plain, s.Algo, s.Params)
}

// Verify dispatches on the stored hash's prefix and returns
// (ok, needsRehash). needsRehash is true when the credential
// matches AND the stored hash uses a different algo than the
// project's current default, OR the stored hash's params are
// weaker than current. Equivalent to passwordhash.Verify(stored,
// plain, s.Algo, s.Params).
func (s Settings) Verify(stored, plain string) (ok, needsRehash bool) {
	return Verify(stored, plain, s.Algo, s.Params)
}

// VerifyAndRotate is the standard login-time helper. It verifies
// the credential, and when the stored hash should be rotated
// (algo change or weakened params) it computes a fresh hash with
// the current Settings and invokes updateFn so the caller can
// persist it.
//
// updateFn errors are returned but never invalidate the
// authentication — verified credentials remain verified even if
// the rotation write fails. Callers log/observe `err` for
// observability and still grant access on ok=true.
//
// updateFn may be nil — VerifyAndRotate then degenerates to the
// equivalent of Verify, returning rotated=false unconditionally.
//
// Returns:
//   - ok      — credential matches
//   - rotated — a fresh hash was computed AND updateFn returned
//     nil; false when no rotation was needed, updateFn was nil,
//     or updateFn / rehash failed
//   - err     — non-nil only when ok=true AND the rehash or
//     updateFn call failed; never an auth failure signal
func (s Settings) VerifyAndRotate(stored, plain string, updateFn func(newHash string) error) (ok, rotated bool, err error) {
	ok, needsRehash := s.Verify(stored, plain)
	if !ok {
		return false, false, nil
	}
	if !needsRehash || updateFn == nil {
		return true, false, nil
	}
	newHash, hashErr := s.Hash(plain)
	if hashErr != nil {
		return true, false, hashErr
	}
	if updateErr := updateFn(newHash); updateErr != nil {
		return true, false, updateErr
	}
	return true, true, nil
}
