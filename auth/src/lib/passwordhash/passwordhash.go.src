// Package passwordhash hashes + verifies credentials for every
// PASSWORD-typed field a wandering-compiler project declares.
//
// REV-151 — invoked by the storage codegen at INSERT / UPDATE
// time (Hash) and by hand-written auth backends at credential
// check time (Verify). The per-project algorithm + tuning live
// in the lock's `password:` block (see
// `docs/specs/storage/password-field.md`); LoadProject reads
// them at runtime startup.
//
// Hash output uses the PHC (Password Hashing Competition)
// encoded format — `$<algo>$<params>$<salt>$<digest>` — so the
// stored bytes self-describe their algorithm. Verify reads the
// prefix to dispatch, which means rotating the project's default
// algorithm (e.g. argon2id → bcrypt) does NOT invalidate
// existing hashes — they continue to verify with their original
// algo until the consumer re-hashes them via the `needsRehash`
// signal Verify returns.
package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Algo identifies a hashing algorithm. The zero value
// (AlgoUnknown) is invalid — callers must pass a concrete algo
// to Hash; Verify auto-detects from the stored prefix.
type Algo int

const (
	AlgoUnknown Algo = iota
	Argon2id
	Bcrypt
	Scrypt
	PBKDF2_SHA256
)

// String returns the canonical lowercase algorithm name used in
// hash prefixes + diagnostic messages. Mirrors the PHC encoded
// algo identifiers (argon2id, 2b for bcrypt, etc.).
func (a Algo) String() string {
	switch a {
	case Argon2id:
		return "argon2id"
	case Bcrypt:
		return "bcrypt"
	case Scrypt:
		return "scrypt"
	case PBKDF2_SHA256:
		return "pbkdf2-sha256"
	}
	return "unknown"
}

// Params carries per-algorithm tuning. Each algo reads only its
// own subset; cross-pollination is ignored. The defaults match
// OWASP 2024 password-storage recommendations.
type Params struct {
	// Argon2id (memory-hard, GPU-resistant). OWASP 2024:
	// m=64MiB, t=3, p=4.
	Argon2idMemKiB  uint32
	Argon2idIters   uint32
	Argon2idThreads uint8

	// Bcrypt cost factor (log2 rounds). OWASP 2024: 12.
	BcryptCost int

	// Scrypt N (CPU/memory cost), r (block size), p
	// (parallelism). OWASP 2024: N=32768, r=8, p=1.
	ScryptN int
	ScryptR int
	ScryptP int

	// PBKDF2-SHA256 iterations. OWASP 2024: 600000.
	PBKDF2Iters int
}

// DefaultParams returns the OWASP-2024 recommended params for
// every supported algorithm. Used when the consumer's lock
// omits the per-algo tuning block.
func DefaultParams() Params {
	return Params{
		Argon2idMemKiB:  65536,
		Argon2idIters:   3,
		Argon2idThreads: 4,
		BcryptCost:      12,
		ScryptN:         32768,
		ScryptR:         8,
		ScryptP:         1,
		PBKDF2Iters:     600000,
	}
}

// saltSize for newly-generated hashes (16 bytes = 128 bits,
// well above the 64-bit minimum every modern algo recommends).
const saltSize = 16

// Hash hashes plain using algo + params, returning the
// PHC-encoded string. Refuses on AlgoUnknown.
func Hash(plain string, algo Algo, params Params) (string, error) {
	if plain == "" {
		return "", errors.New("passwordhash: empty plaintext")
	}
	switch algo {
	case Argon2id:
		return hashArgon2id(plain, params)
	case Bcrypt:
		return hashBcrypt(plain, params)
	case Scrypt:
		return hashScrypt(plain, params)
	case PBKDF2_SHA256:
		return hashPBKDF2(plain, params)
	}
	return "", fmt.Errorf("passwordhash: unknown algo %d", algo)
}

// Verify constant-time-compares plain against the stored hash.
// The algorithm is auto-detected from the stored prefix; currentAlgo
// + currentParams describe the project's current default and feed
// the needsRehash signal.
//
//	ok          — credential matches
//	needsRehash — credential matches AND the stored hash's algo or
//	              params are weaker than the current project default.
//	              When true, caller is expected to call Hash(plain,
//	              currentAlgo, currentParams) and update the stored
//	              hash. Walking-skeleton consumers may ignore.
//
// On unreadable / malformed `stored`, Verify returns (false, false).
// Verify is constant-time-safe per-algorithm — timing reveals nothing
// about which characters matched.
func Verify(stored, plain string, currentAlgo Algo, currentParams Params) (ok, needsRehash bool) {
	if stored == "" || plain == "" {
		return false, false
	}
	storedAlgo := detectAlgo(stored)
	switch storedAlgo {
	case Argon2id:
		ok = verifyArgon2id(stored, plain)
	case Bcrypt:
		ok = verifyBcrypt(stored, plain)
	case Scrypt:
		ok = verifyScrypt(stored, plain)
	case PBKDF2_SHA256:
		ok = verifyPBKDF2(stored, plain)
	default:
		return false, false
	}
	if !ok {
		return false, false
	}
	needsRehash = storedAlgo != currentAlgo || paramsWeakerThan(storedAlgo, stored, currentParams)
	return ok, needsRehash
}

// detectAlgo reads the leading PHC prefix on `stored` and returns
// the matching Algo. Bcrypt's `$2a$ / $2b$ / $2y$` family is
// normalised to Bcrypt; argon2id is recognised as a single algo
// (argon2i / argon2d aren't supported — they're listed as
// AlgoUnknown so misconfigured deploys fail closed).
func detectAlgo(stored string) Algo {
	switch {
	case strings.HasPrefix(stored, "$argon2id$"):
		return Argon2id
	case strings.HasPrefix(stored, "$2a$") ||
		strings.HasPrefix(stored, "$2b$") ||
		strings.HasPrefix(stored, "$2y$"):
		return Bcrypt
	case strings.HasPrefix(stored, "$scrypt$"):
		return Scrypt
	case strings.HasPrefix(stored, "$pbkdf2-sha256$"):
		return PBKDF2_SHA256
	}
	return AlgoUnknown
}

// paramsWeakerThan reports whether the parameters embedded in
// `stored` are weaker than `current` for the given algorithm.
// Used by Verify to flag hashes that should be re-hashed with
// stronger params even when the algorithm itself didn't change.
// Returns false on parse failure (don't spuriously trigger
// rehash on malformed input).
func paramsWeakerThan(algo Algo, stored string, current Params) bool {
	switch algo {
	case Argon2id:
		_, m, t, p, _, _, err := parseArgon2id(stored)
		if err != nil {
			return false
		}
		return m < current.Argon2idMemKiB ||
			t < current.Argon2idIters ||
			p < current.Argon2idThreads
	case Bcrypt:
		cost, err := bcrypt.Cost([]byte(stored))
		if err != nil {
			return false
		}
		return cost < current.BcryptCost
	case Scrypt:
		_, n, r, p, _, _, err := parseScrypt(stored)
		if err != nil {
			return false
		}
		return n < current.ScryptN || r < current.ScryptR || p < current.ScryptP
	case PBKDF2_SHA256:
		_, iters, _, _, err := parsePBKDF2(stored)
		if err != nil {
			return false
		}
		return iters < current.PBKDF2Iters
	}
	return false
}

// ---- argon2id ----

func hashArgon2id(plain string, p Params) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: rand salt: %w", err)
	}
	digest := argon2.IDKey([]byte(plain), salt, p.Argon2idIters, p.Argon2idMemKiB, p.Argon2idThreads, 32)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Argon2idMemKiB,
		p.Argon2idIters,
		p.Argon2idThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func verifyArgon2id(stored, plain string) bool {
	version, m, t, p, salt, digest, err := parseArgon2id(stored)
	if err != nil {
		return false
	}
	if version != argon2.Version {
		// Version mismatch — refuse rather than risk a silent
		// crypto-shape change. Stored hashes from a different
		// argon2 version need a one-shot re-hash migration.
		return false
	}
	candidate := argon2.IDKey([]byte(plain), salt, t, m, p, uint32(len(digest)))
	return subtle.ConstantTimeCompare(candidate, digest) == 1
}

func parseArgon2id(stored string) (version int, memKiB, iters uint32, threads uint8, salt, digest []byte, err error) {
	// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<digest>
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, 0, nil, nil, errors.New("passwordhash: malformed argon2id prefix")
	}
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: parse version: %w", err)
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memKiB, &iters, &threads); err != nil {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: parse params: %w", err)
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: decode salt: %w", err)
	}
	if digest, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: decode digest: %w", err)
	}
	return version, memKiB, iters, threads, salt, digest, nil
}

// ---- bcrypt ----

func hashBcrypt(plain string, p Params) (string, error) {
	cost := p.BcryptCost
	if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	}
	if cost > bcrypt.MaxCost {
		cost = bcrypt.MaxCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", fmt.Errorf("passwordhash: bcrypt: %w", err)
	}
	return string(hash), nil
}

func verifyBcrypt(stored, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plain)) == nil
}

// ---- scrypt ----

const scryptKeyLen = 32

func hashScrypt(plain string, p Params) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: rand salt: %w", err)
	}
	digest, err := scrypt.Key([]byte(plain), salt, p.ScryptN, p.ScryptR, p.ScryptP, scryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("passwordhash: scrypt: %w", err)
	}
	return fmt.Sprintf(
		"$scrypt$n=%d,r=%d,p=%d$%s$%s",
		p.ScryptN, p.ScryptR, p.ScryptP,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func verifyScrypt(stored, plain string) bool {
	_, n, r, p, salt, digest, err := parseScrypt(stored)
	if err != nil {
		return false
	}
	candidate, err := scrypt.Key([]byte(plain), salt, n, r, p, len(digest))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(candidate, digest) == 1
}

func parseScrypt(stored string) (_ struct{}, n, r, p int, salt, digest []byte, err error) {
	// Format: $scrypt$n=32768,r=8,p=1$<salt>$<digest>
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[1] != "scrypt" {
		return struct{}{}, 0, 0, 0, nil, nil, errors.New("passwordhash: malformed scrypt prefix")
	}
	if _, err = fmt.Sscanf(parts[2], "n=%d,r=%d,p=%d", &n, &r, &p); err != nil {
		return struct{}{}, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: parse params: %w", err)
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return struct{}{}, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: decode salt: %w", err)
	}
	if digest, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return struct{}{}, 0, 0, 0, nil, nil, fmt.Errorf("passwordhash: decode digest: %w", err)
	}
	return struct{}{}, n, r, p, salt, digest, nil
}

// ---- pbkdf2-sha256 ----

const pbkdf2KeyLen = 32

func hashPBKDF2(plain string, p Params) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: rand salt: %w", err)
	}
	digest := pbkdf2.Key([]byte(plain), salt, p.PBKDF2Iters, pbkdf2KeyLen, sha256.New)
	return fmt.Sprintf(
		"$pbkdf2-sha256$i=%d$%s$%s",
		p.PBKDF2Iters,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func verifyPBKDF2(stored, plain string) bool {
	_, iters, salt, digest, err := parsePBKDF2(stored)
	if err != nil {
		return false
	}
	candidate := pbkdf2.Key([]byte(plain), salt, iters, len(digest), sha256.New)
	return subtle.ConstantTimeCompare(candidate, digest) == 1
}

func parsePBKDF2(stored string) (_ struct{}, iters int, salt, digest []byte, err error) {
	// Format: $pbkdf2-sha256$i=600000$<salt>$<digest>
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return struct{}{}, 0, nil, nil, errors.New("passwordhash: malformed pbkdf2-sha256 prefix")
	}
	if !strings.HasPrefix(parts[2], "i=") {
		return struct{}{}, 0, nil, nil, errors.New("passwordhash: pbkdf2 missing iterations")
	}
	iters, err = strconv.Atoi(parts[2][2:])
	if err != nil {
		return struct{}{}, 0, nil, nil, fmt.Errorf("passwordhash: parse iters: %w", err)
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return struct{}{}, 0, nil, nil, fmt.Errorf("passwordhash: decode salt: %w", err)
	}
	if digest, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return struct{}{}, 0, nil, nil, fmt.Errorf("passwordhash: decode digest: %w", err)
	}
	return struct{}{}, iters, salt, digest, nil
}
