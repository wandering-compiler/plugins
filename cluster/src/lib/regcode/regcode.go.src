// Package regcode holds a relay's one-time registration codes.
//
// A worker joins a relay by presenting a code the relay minted, and receives a
// certificate for the key it generated itself. The code is the whole of the
// enrolment credential, so it is treated like a ticket: minted by the relay,
// held in its memory and nowhere else, single use, and short-lived. A relay
// restart voids every outstanding code — the operator asks for another — and
// nothing about a code is ever written down where it could leak later.
package regcode

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrInvalid covers unknown, spent and expired codes with one error, for the
// reason relaycore.ErrNoSuchTicket does: which of the three it was tells a
// guesser whether a code ever existed.
var ErrInvalid = errors.New("regcode: no such registration code")

// Store is one relay's outstanding codes.
type Store struct {
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex
	// codes is keyed by the code's SHA-256, so a heap dump of a relay does
	// not hand out working codes.
	codes map[[32]byte]time.Time
}

// New makes a store whose codes live for ttl. Now is a test seam; nil uses
// the real clock.
func New(ttl time.Duration, now func() time.Time) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("regcode: a code lifetime must be positive, got %s", ttl)
	}
	if now == nil {
		now = time.Now
	}
	return &Store{ttl: ttl, now: now, codes: map[[32]byte]time.Time{}}, nil
}

// Issue mints a code and returns it with its expiry.
//
// 120 random bits, written as base32 in groups of four so a person can read it
// off a page and type it into a tool without guessing at 0/O or 1/l.
func (s *Store) Issue() (string, time.Time, error) {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("regcode: no entropy for a code: %w", err)
	}
	raw := base32.StdEncoding.EncodeToString(b[:]) // 24 chars, no padding
	groups := make([]string, 0, len(raw)/4)
	for i := 0; i < len(raw); i += 4 {
		groups = append(groups, raw[i:i+4])
	}
	code := strings.Join(groups, "-")

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	expires := now.Add(s.ttl)
	s.codes[digest(code)] = expires
	return code, expires, nil
}

// Redeem spends a code. It succeeds exactly once, and only before expiry.
func (s *Store) Redeem(code string) error {
	key := digest(normalise(code))
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.codes[key]
	if !ok {
		return ErrInvalid
	}
	delete(s.codes, key)
	if !s.now().Before(expires) {
		return ErrInvalid
	}
	return nil
}

// Outstanding is how many unexpired codes are held — for an operator, and for
// tests.
func (s *Store) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	return len(s.codes)
}

func (s *Store) sweepLocked(now time.Time) {
	for k, exp := range s.codes {
		if !now.Before(exp) {
			delete(s.codes, k)
		}
	}
}

// normalise forgives what a person does to a code in transit: case, and
// surrounding space. The dashes are part of the code as issued.
func normalise(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func digest(code string) [32]byte { return sha256.Sum256([]byte(code)) }
