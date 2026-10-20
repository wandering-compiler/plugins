package textfilter

import (
	"strings"
	"testing"
)

func latin(t *testing.T, names ...string) *Scripts {
	t.Helper()
	if len(names) == 0 {
		names = []string{"Latin"}
	}
	s, err := NewScripts(names)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScripts(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		// The case that asked for it: Thai glued to the
		// end of a Czech sentence.
		{"a leaked token glued to the sentence", "… tu jsem v metodice Oberbank nenašel.ข้อความเต็ม", "… tu jsem v metodice Oberbank nenašel."},
		{"between two words", "Výsledek 统计 je hotový.", "Výsledek je hotový."},
		{"before punctuation", "Hotovo 완료.", "Hotovo."},
		{"inside a word", "Oberbankข้อ účet", "Oberbank účet"},
		{"at the end of a line, keeping the line break", "první řádek 終\ndruhý", "první řádek\ndruhý"},
		{"Cyrillic and Greek are scripts too", "ano да ναι", "ano"},
		// What must survive: Czech diacritics (Latin + combining), digits,
		// punctuation, symbols, emoji with a zero-width joiner.
		{"diacritics, digits, punctuation, emoji", "Žluťoučký kůň: 3× 42 % — 👨\u200d👩\u200d👧 ✓", "Žluťoučký kůň: 3× 42 % — 👨\u200d👩\u200d👧 ✓"},
		{"decomposed diacritics", "cafe\u0301", "cafe\u0301"},
		{"indentation and code are not reflowed", "  - položka  a\n    x ,y", "  - položka  a\n    x ,y"},
		{"nothing to remove returns the text as is", "plain text  with  spaces ", "plain text  with  spaces "},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := latin(t).Apply(c.in); got != c.want {
				t.Errorf("Apply(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// A Thai combining vowel after the removed run goes with it: it is Thai, and
// an Inherited mark right after a dropped letter belongs to that letter.
func TestScripts_MarksGoWithTheirLetter(t *testing.T) {
	if got := latin(t).Apply("ok ก\u0e34\u0301 ok"); got != "ok ok" {
		t.Fatalf("got %q", got)
	}
}

func TestScripts_SeveralAllowed(t *testing.T) {
	s := latin(t, "latin", " Cyrillic ", "Latin")
	if got := s.Apply("Привет, světe! 你好"); got != "Привет, světe!" {
		t.Fatalf("got %q", got)
	}
	if s.Name() != "scripts(Latin,Cyrillic)" {
		t.Fatalf("name %q", s.Name())
	}
}

func TestNewScripts_Refusals(t *testing.T) {
	if _, err := NewScripts([]string{"Latn"}); err == nil || !strings.Contains(err.Error(), `"Latn"`) || !strings.Contains(err.Error(), "Latin") {
		t.Errorf("an unknown script: %v", err)
	}
	for _, names := range [][]string{nil, {""}, {"Common", "Inherited"}} {
		if _, err := NewScripts(names); err == nil {
			t.Errorf("NewScripts(%q) allowed no script and was accepted", names)
		}
	}
}

func TestInvisible(t *testing.T) {
	in := "a\u200bb\ufeffc\u202ed\u2066e\u0007f\ufffdg\th\ni\r\nj 👨\u200d👩 k\u200cl \u200em"
	want := "abcdefg\th\ni\r\nj 👨\u200d👩 k\u200cl \u200em"
	if got := (Invisible{}).Apply(in); got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if got := (Invisible{}).Apply("clean"); got != "clean" {
		t.Fatalf("clean text changed: %q", got)
	}
}

func TestChain(t *testing.T) {
	c := Chain{Invisible{}, latin(t)}
	if got := c.Apply("Ano\u200b, ok ข้อ"); got != "Ano, ok" {
		t.Fatalf("got %q", got)
	}
	if got := (Chain{}).Apply("x"); got != "x" {
		t.Fatalf("empty chain changed the text: %q", got)
	}
}
