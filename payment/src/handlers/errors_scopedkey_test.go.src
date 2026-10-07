package handlers

import "testing"

// A separator-joined hash let one part's bytes shift into the next: with NUL
// as the separator, ("u\x00v", "k") and ("u", "v\x00k") were one stored key —
// a grant for one principal answered as a retry of another's.
func TestScopedKey_PartsCannotShiftAcrossEachOther(t *testing.T) {
	cases := [][2][]string{
		{{"credit", "grant", "u\x00v", "k"}, {"credit", "grant", "u", "v\x00k"}},
		{{"credit", "grant", "ab", "c"}, {"credit", "grant", "a", "bc"}},
		{{"credit", "grant", "", "x"}, {"credit", "grant", "x", ""}},
	}
	for _, c := range cases {
		if a, b := scopedKey(c[0]...), scopedKey(c[1]...); a == b {
			t.Errorf("%q and %q share the stored key %s", c[0], c[1], a)
		}
	}
	if got, again := scopedKey("credit", "spend", "u", "k"), scopedKey("credit", "spend", "u", "k"); got != again || len(got) != 67 {
		t.Errorf("a retry must reproduce the same 67-byte key: %q vs %q", got, again)
	}
}
