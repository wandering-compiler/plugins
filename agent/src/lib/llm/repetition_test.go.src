package llm

import "testing"

// The guard has to fire on a stuck model and stay silent on prose that merely
// repeats itself for good reasons. The second half is the one that matters:
// a false positive truncates a correct answer in front of the person who asked.
func TestRepeating(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		// A model stuck on a fragment. This is the shape the guard exists for.
		{"a stuck fragment", "Odpověď je: " + repeat("nevím, nevím, ", 20), true},
		{"a stuck word", repeat("ano ", 40), true},
		// Multibyte: the check compares bytes, and a Czech fragment is as
		// periodic in bytes as it is on screen — only with a larger period.
		{"stuck on multibyte", repeat("žádné údaje, ", 20), true},

		// Genuine prose must survive. A table of prices, a list — these repeat
		// structure without repeating a fragment, and the window is sized so
		// the surrounding sentence dilutes them.
		{"ordinary prose", "Byt se nachází v Brně, má 3 pokoje a je po rekonstrukci. Cena je 5 900 000 Kč včetně provize a poplatků.", false},
		{"a short list", "Nabídka: 1) byt 2+kk v Praze, 2) dům se zahradou v Brně, 3) chata u Berouna, 4) pozemek v Plzni.", false},

		// Too short to judge. Deciding on a fragment this small would fire on
		// ordinary punctuation.
		{"under the window", "ano ano ano", false},
		{"empty", "", false},

		// Two repeats is a rhyme, not a loop. Note what holds this up: the 90%
		// threshold, NOT the `/3` clause that reads as if it did — see the note
		// in repetition.go. This row passes either way, and saying so here
		// keeps it from being read as proof of a mechanism it does not touch.
		{"twice is not a loop", "Původní cena byla 5 900 000 Kč, nová cena je 5 900 000 Kč, rozdíl tedy žádný není vůbec.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := repeating(tc.text); got != tc.want {
				t.Errorf("repeating(%q…) = %v, want %v", head(tc.text, 40), got, tc.want)
			}
		})
	}
}

// A model that drifts a character here and there is still stuck — demanding
// perfection would miss exactly the cases that look worst to a reader.
func TestRepeatingToleratesDrift(t *testing.T) {
	text := ""
	for i := 0; i < 20; i++ {
		text += "nevím, nevim, " // note the drifting diacritic
	}
	if !repeating(text) {
		t.Error("a drifting loop was not detected")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
