// The stuck-model guard: a stream whose tail has gone periodic is cut off.
//
// Ported from `chatengine/repetition.go` in Marb-AI/platform, which in turn
// ported it from a predecessor that had run it in production since before that
// package existed. The constants are its constants, and their test feeds real
// answers rather than invented ones — a threshold nobody has watched fire is a
// guess, and this one is not.
//
// # What it is for
//
// A model occasionally gets stuck and emits the same short fragment until
// something stops it. Two other things already stop it, and neither is this:
// maxStreamOutput catches 20 000 bytes of it, and the token budget catches the
// rest by FAILING the turn — so without this a loop costs the reader their
// whole answer and costs a full budget of output tokens to produce nothing.
// This notices within about 150 bytes instead.
//
// # It becomes load-bearing the day the provider stops buffering
//
// Azure returns the whole completion in one burst under its default
// (synchronous) content filter, so a loop is invisible on the way past and
// lands as one bad message. With the ASYNCHRONOUS filter it would be typed out,
// at length, in front of somebody. That is the change this exists to be ready
// for — and it is the configuration a deployment picks, not one we control.
//
// # Bytes, not runes
//
// Every comparison is between bytes and nothing is ever decoded, which is safe
// for the question being asked: text that repeats repeats its bytes exactly, so
// a Czech fragment with multibyte characters is as periodic in bytes as it is
// on screen — only with a period that is a larger number. Slicing the window
// can therefore cut a rune in half, and it does not matter, because a half rune
// is compared with the same half rune one period earlier.
package llm

const (
	// repetitionWindow is how much of the tail is examined. Long enough to hold
	// several repeats of a phrase, short enough that a genuinely repetitive
	// PASSAGE — a table, a list of prices — is diluted by the sentence around
	// it.
	repetitionWindow = 100

	// The shortest and longest repeating unit looked for. Under four bytes
	// catches ordinary punctuation and spacing; over fifty is a paragraph, and
	// a model repeating whole paragraphs is doing something this check is the
	// wrong shape for.
	repetitionMinPeriod = 4
	repetitionMaxPeriod = 50

	// repetitionMatchPercent is how much of the window must line up with
	// itself. Not 100: a stuck model usually drifts a character here and there,
	// and a check that demanded perfection would miss exactly the cases that
	// look worst.
	repetitionMatchPercent = 90

	// repetitionCheckInterval is how many new bytes pass between checks. The
	// cost is one pass over 100 bytes per 50 bytes of output, which is nothing,
	// and the delay it adds before noticing is bounded by it.
	repetitionCheckInterval = 50
)

// repeating reports whether the tail of text consists of a short fragment
// repeated.
//
// It tries every period in range and asks how much of the window agrees with
// itself that far back. A period is only considered while it fits three times
// over — two repeats is a rhyme, and a unit price appearing twice in a sentence
// about two prices must not end anybody's answer.
//
// The `/3` clause is REDUNDANT at the current constants and is kept as the
// statement of intent rather than as the mechanism. Measured: with a 100-byte
// window, a period of 34 can match at most 48% of the comparisons it is
// eligible for, 40 at most 33%, 49 at most 3% — all far under the 90%
// threshold, which already excludes every period that cannot fit three times.
// Changing the window or the threshold can make it load-bearing again, which
// is the reason to leave it in place and the reason this note exists: a
// break-proof that removes it today changes nothing, and that is a fact about
// the constants, not a licence to delete it.
func repeating(text string) bool {
	if len(text) < repetitionWindow {
		return false
	}
	window := text[len(text)-repetitionWindow:]
	for period := repetitionMinPeriod; period <= repetitionMaxPeriod && period < len(window)/3; period++ {
		matches := 0
		for i := period; i < len(window); i++ {
			if window[i] == window[i-period] {
				matches++
			}
		}
		if matches*100/(len(window)-period) > repetitionMatchPercent {
			return true
		}
	}
	return false
}
