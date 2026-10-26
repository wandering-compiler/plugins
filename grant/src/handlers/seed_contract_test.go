package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A project seeds an approved envelope by fixture with the values the plugin's
// own statements write and read (SPEC.md, "Seeding an approved envelope"):
// status 'approved' and approved_slot 'approved', the previous approved one
// 'superseded' with approved_slot NULL. The constants are that contract; the
// statements must use exactly them, or a seeded envelope stops being read
// publicly — or two approved versions of one organization pass the index.
func TestEnvelopeStatementsUseTheContractValues(t *testing.T) {
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "proto", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mutations, queries := read("mutations/grant_mutation.proto"), read("queries/grant_query.proto")
	for _, want := range []string{
		"status = '" + StatusApproved + "', approved_slot = '" + ApprovedSlot + "'",
		"status = '" + StatusSuperseded + "', approved_slot = NULL",
		"status = '" + StatusProposed + "'",
		"status = '" + StatusRejected + "'",
	} {
		if !strings.Contains(mutations, want) {
			t.Errorf("grant_mutation.proto writes no %q — the seeding contract and the statements disagree", want)
		}
	}
	if !strings.Contains(queries, "e.status = '"+StatusApproved+"'") {
		t.Errorf("grant_query.proto does not read the approved envelope by status %q", StatusApproved)
	}
}
