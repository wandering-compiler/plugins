package regcode

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// A code works ONCE. It is the whole enrolment credential, so a second use is
// a second worker on one operator's say-so.
func TestRedeem_IsSingleUse(t *testing.T) {
	s, err := New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Redeem(code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.Redeem(code); !errors.Is(err, ErrInvalid) {
		t.Errorf("second use: %v, want ErrInvalid", err)
	}
}

// And only before it expires; and an expired code reads like an invented one.
func TestRedeem_ExpiresAndIsIndiscriminate(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	s, err := New(time.Minute, c.now)
	if err != nil {
		t.Fatal(err)
	}
	code, exp, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(c.now().Add(time.Minute)) {
		t.Errorf("expiry = %v, want issue time + TTL", exp)
	}
	c.add(time.Minute)
	expired := s.Redeem(code)
	invented := s.Redeem("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	if !errors.Is(expired, ErrInvalid) || !errors.Is(invented, ErrInvalid) {
		t.Fatalf("expired: %v, invented: %v — want ErrInvalid for both", expired, invented)
	}
	if expired.Error() != invented.Error() {
		t.Error("an expired code and an invented one are distinguishable")
	}
}

// A person copies a code off a page; case and stray spaces are forgiven.
func TestRedeem_ForgivesCaseAndSpace(t *testing.T) {
	s, _ := New(time.Minute, nil)
	code, _, _ := s.Issue()
	if err := s.Redeem("  " + strings.ToLower(code) + "\n"); err != nil {
		t.Fatalf("a code typed in lower case with spaces was refused: %v", err)
	}
}

func TestIssue_CodesAreDistinctAndReadable(t *testing.T) {
	s, _ := New(time.Minute, nil)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, _, err := s.Issue()
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatalf("code %s issued twice", code)
		}
		seen[code] = true
		if len(code) != 29 || strings.ContainsAny(code, "018") {
			t.Fatalf("code %q is not 6 groups of 4 base32 characters", code)
		}
	}
	if s.Outstanding() != 50 {
		t.Errorf("outstanding = %d, want 50", s.Outstanding())
	}
}
