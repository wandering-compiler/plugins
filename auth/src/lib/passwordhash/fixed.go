package passwordhash

import (
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

// The cost of FixedArgon2idHex. FIXED, not the deployment's password
// parameters: a value it produced is recomputed exactly at every later
// lookup, so changing any of these orphans every stored value (a change needs
// a new function tried first and this one kept as the fallback). OWASP's
// argon2id minimum.
const (
	fixedTime    = 2
	fixedMemory  = 19 * 1024 // KiB
	fixedThreads = 1
	fixedKeyLen  = 32 // bytes; 64 hex characters
)

// FixedArgon2idHex is argon2id of secret under salt with fixed parameters
// (t=2, 19 MiB, 1 lane, 32 bytes), hex-encoded: a deterministic slow hash for
// a low-entropy secret that is looked up BY its hash, where a random salt
// stored beside the value would force a read-then-verify of every candidate
// row. The caller derives salt from what scopes the secret (an account), so a
// guess is a guess against that scope only.
func FixedArgon2idHex(secret string, salt []byte) string {
	return hex.EncodeToString(argon2.IDKey([]byte(secret), salt, fixedTime, fixedMemory, fixedThreads, fixedKeyLen))
}
