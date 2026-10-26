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
	mutations, queries, models := read("mutations/grant_mutation.proto"), read("queries/grant_query.proto"), read("types/models.proto")
	// Each literal in the form only its own statement uses: the insert's SET
	// list, the decisions' SET lists. A guard (`AND status = 'proposed'`) does
	// not count as the insert writing it.
	for _, want := range []string{
		"\"status = '" + StatusProposed + "', \"",
		"SET status = '" + StatusApproved + "', approved_slot = '" + ApprovedSlot + "'",
		"SET status = '" + StatusSuperseded + "', approved_slot = NULL WHERE org_id = :pending.org_id AND status = '" + StatusApproved + "'",
		"SET status = '" + StatusRejected + "'",
		"WHERE id = :id AND status = '" + StatusProposed + "' RETURNING",
	} {
		if !strings.Contains(mutations, want) {
			t.Errorf("grant_mutation.proto has no %q — the seeding contract and the statements disagree", want)
		}
	}
	for _, want := range []string{
		"e.status = '" + StatusApproved + "'\"",
		"e.status = '" + StatusProposed + "' ORDER BY",
	} {
		if !strings.Contains(queries, want) {
			t.Errorf("grant_query.proto has no %q — the seeding contract and the reads disagree", want)
		}
	}
	// The one-per-organization half of the contract is the index, and a
	// seeded slot value has to fit its column.
	if !strings.Contains(models, `{ unique: true, fields: [{ name: "org_id" }, { name: "approved_slot" }] }`) {
		t.Error("models.proto has no unique (org_id, approved_slot) index — a seeded approved envelope is no longer held to one per organization")
	}
	if !strings.Contains(models, `string approved_slot    = 20 [(w17.field) = { type: CHAR, max_len: 8, null: true }];`) || len(ApprovedSlot) > 8 {
		t.Errorf("approved_slot is not a nullable CHAR(8) holding %q", ApprovedSlot)
	}
}
