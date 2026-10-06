package llm

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// a consumer. Both model-call handlers logged the provider error with `%v`,
// justified by a comment saying the deployment URL is acceptable in a log. The
// full text also carries the RESPONSE BODY, and this package's own doc records
// that the body sometimes quotes the prompt — so user input reached a log that
// is shipped, aggregated and kept far longer than the request.
//
// This is a SOURCE gate rather than a behavioural one, and deliberately so: a
// faithful `*openai.Error` cannot be built by hand (its own Error() needs the
// response the SDK attaches), so a hand-made one would prove something about a
// value the real path never produces — the shape of test I keep being caught
// by. What can be stated exactly is the rule that was broken: a provider error
// never reaches a log verb raw.
func TestNoHandlerLogsARawProviderError(t *testing.T) {
	// Line-based, and that matters: the first version of this gate used
	// `log\.Printf\([^)]*err\)` and was BLIND, because `[^)]*` cannot cross the
	// `)` inside the format string (`"... (model %q): %v"`). It passed while the
	// defect was reinstated. Match a log call whose LAST argument is the bare
	// error instead.
	raw := regexp.MustCompile(`log\.(Printf|Println|Fatalf)\(.*,\s*err\s*\)\s*$`)
	root := filepath.Join("..", "..", "handlers")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read handlers: %v — if this package moved, move the gate with it", err)
	}
	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(root, e.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		checked++
		for _, line := range strings.Split(string(body), "\n") {
			m := strings.TrimSpace(line)
			if !raw.MatchString(m) {
				continue
			}
			if strings.Contains(m, "ProviderLogLine") {
				continue
			}
			t.Errorf("%s logs an error raw: %s\n"+
				"a provider error carries the response body, which can quote the prompt — "+
				"use llm.ProviderLogLine(err)", e.Name(), m)
		}
	}
	// An assertion that reads no files passes for the wrong reason.
	if checked == 0 {
		t.Fatal("no handler files were read — the gate proved nothing")
	}
}

// A non-provider error (transport, context) carries no body and is the only
// clue the caller has, so it is passed through rather than swallowed.
func TestProviderLogLineKeepsANonProviderError(t *testing.T) {
	line := ProviderLogLine(errors.New("dial tcp: i/o timeout"))
	if !strings.Contains(line, "i/o timeout") {
		t.Fatalf("a transport error must survive: %s", line)
	}
}
