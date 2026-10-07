package workeradmit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCheckClaims(t *testing.T) {
	for _, tc := range []struct {
		name, claim, device string
		says                string // "" = accepted
	}{
		{"plain", "acme-1", "dev-1", ""},
		{"empty", "", "", ""},
		{"at the limit, multibyte", strings.Repeat("ř", MaxClaimLen), "", ""},
		{"name over the limit", strings.Repeat("h", MaxClaimLen+1), "", "name is 129 characters long"},
		{"device over the limit", "", strings.Repeat("d", 200), "device id is 200 characters long"},
		{"NUL", "a\x00b", "", "control character U+0000"},
		{"DEL", "", "a\x7fb", "control character U+007F"},
		{"C1 control", "a\u0085b", "", "control character U+0085"},
		{"invalid UTF-8", "a\xffb", "", "not valid UTF-8"},
		{"right-to-left override", "acme-\u202e1", "", "format character U+202E"},
		{"zero-width space", "", "dev\u200b1", "format character U+200B"},
		{"byte order mark", "\ufeffacme-1", "", "format character U+FEFF"},
	} {
		err := CheckClaims(tc.claim, tc.device)
		switch {
		case tc.says == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says)):
			t.Errorf("%s: err = %v, want one saying %q", tc.name, err, tc.says)
		}
	}
}

// Whatever comes in, what comes out passes CheckClaims — that is the whole
// contract — and a claim that already did is returned unchanged.
func TestSanitizeClaim(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		changed  bool
	}{
		{"acme-1", "acme-1", false},
		{"", "", false},
		{"already \uFFFD here", "already \uFFFD here", false},
		{strings.Repeat("ř", MaxClaimLen), strings.Repeat("ř", MaxClaimLen), false},
		{strings.Repeat("ř", MaxClaimLen+5), strings.Repeat("ř", MaxClaimLen), true},
		{"a\x00b\nc", "a\uFFFDb\uFFFDc", true},
		{"a\xffb", "a\uFFFDb", true},
		{"acme-\u202e1\u200b", "acme-\uFFFD1\uFFFD", true},
	} {
		got, changed := SanitizeClaim(tc.in)
		if got != tc.want || changed != tc.changed {
			t.Errorf("SanitizeClaim(%q) = %q, %v; want %q, %v", tc.in, got, changed, tc.want, tc.changed)
		}
		if err := CheckClaims(got, got); err != nil {
			t.Errorf("SanitizeClaim(%q) = %q, which CheckClaims refuses: %v", tc.in, got, err)
		}
		if utf8.RuneCountInString(got) > MaxClaimLen {
			t.Errorf("SanitizeClaim(%q) left %d characters", tc.in, utf8.RuneCountInString(got))
		}
	}
}
