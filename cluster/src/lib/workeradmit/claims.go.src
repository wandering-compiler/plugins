package workeradmit

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxClaimLen is the longest worker name or device id the control plane's
// registry holds, in characters: RecordWorkerReq.name / device_id, max_len
// 128.
const MaxClaimLen = 128

// CheckClaims says why a worker's name or device id could not be recorded by
// the control plane's registry, or nil when both can.
//
// Two rules, both the registry's: at most MaxClaimLen characters (not bytes),
// and no control character. The second is not cosmetic — Postgres refuses a
// NUL in text outright (SQLSTATE 22021), which reaches the control plane's
// sweep as an Internal error, indistinguishable there from the database being
// down, and so aborts every sweep for as long as that worker is attached.
//
// A Unicode FORMAT character (category Cf: U+202E RIGHT-TO-LEFT OVERRIDE, the
// zero-width space, joiner and non-joiner, U+FEFF) is refused with them. The
// registry would store one, but a name is what an operator reads to decide
// whom to ban, and an invisible or reordering character makes two different
// claims print alike — "acme-1" and "acme-1" with a zero-width space — or one
// print as another.
//
// A worker checks its own configuration with it before it enrols, and a relay
// refuses an enrolment that breaks it; see SanitizeClaim for a worker that is
// ALREADY enrolled.
func CheckClaims(name, deviceID string) error {
	for _, c := range []struct{ what, v string }{{"name", name}, {"device id", deviceID}} {
		if n := utf8.RuneCountInString(c.v); n > MaxClaimLen {
			return fmt.Errorf("the worker's %s is %d characters long, the most a relay accepts is %d — configure a shorter one",
				c.what, n, MaxClaimLen)
		}
		if !utf8.ValidString(c.v) {
			return fmt.Errorf("the worker's %s is not valid UTF-8 — configure one that is", c.what)
		}
		if i := strings.IndexFunc(c.v, unicode.IsControl); i >= 0 {
			r, _ := utf8.DecodeRuneInString(c.v[i:])
			return fmt.Errorf("the worker's %s contains the control character %U — configure one without", c.what, r)
		}
		if i := strings.IndexFunc(c.v, isFormat); i >= 0 {
			r, _ := utf8.DecodeRuneInString(c.v[i:])
			return fmt.Errorf("the worker's %s contains the invisible format character %U — configure one without", c.what, r)
		}
	}
	return nil
}

// SanitizeClaim makes a claim the registry can record: every control
// character, format character (see CheckClaims) and invalid byte becomes
// U+FFFD, and what remains is cut to
// MaxClaimLen characters. changed says whether anything was altered.
//
// For a worker that already HOLDS a certificate, whose claims were never
// checked when it enrolled: refusing it at every attach would take a working
// machine out of the fleet on a relay upgrade, for a label. Its identity is
// its key, not its name, so a shortened name loses nothing an operator acts
// on.
func SanitizeClaim(s string) (clean string, changed bool) {
	var b strings.Builder
	n := 0
	for i, r := range s {
		if n == MaxClaimLen {
			return b.String(), true
		}
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				changed = true
			}
		}
		if unicode.IsControl(r) || isFormat(r) {
			r, changed = utf8.RuneError, true
		}
		b.WriteRune(r)
		n++
	}
	return b.String(), changed
}

// isFormat reports a Unicode format character (category Cf): invisible, or
// changing how the text around it is ordered or joined.
func isFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }
