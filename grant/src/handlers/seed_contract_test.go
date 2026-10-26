package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	pb "github.com/wandering-compiler/plugins/grant/gen/pb"
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
	// Field alignment is cosmetic: match the declaration, not its padding.
	slot := regexp.MustCompile(`string\s+approved_slot\s*=\s*\d+\s*\[\(w17\.field\)\s*=\s*\{\s*type:\s*CHAR,\s*max_len:\s*(\d+),\s*null:\s*true\s*\}\]`).FindStringSubmatch(models)
	if slot == nil {
		t.Fatal("models.proto has no nullable CHAR approved_slot")
	}
	if n, _ := strconv.Atoi(slot[1]); len(ApprovedSlot) > n {
		t.Errorf("approved_slot is CHAR(%d), too short for %q", n, ApprovedSlot)
	}
}

// The public read holds an approved envelope to the proposal's rules field by
// field: a seeded row is checked nowhere else, and what it serves reaches the
// consent, invitation and sign-in pages. A field that breaks a rule is left
// out; the envelope and its good fields stay.
func TestGetOrgEnvelope_LeavesOutAFieldThatBreaksTheRules(t *testing.T) {
	got := publicFields(&pb.EnvelopeFields{
		DisplayName:  "Acme",
		LogoLightUrl: "https://acme.example/logo.svg",
		WebsiteUrl:   "javascript:alert(1)",
		SupportUrl:   "http://evil.example/help",
		PrivacyUrl:   "https://user:pw@acme.example/privacy",
		AccentColor:  "red",
		VerifiedHost: "ACME.example",
		OperatedBy:   "Acme Ltd",
	})
	if got.GetDisplayName() != "Acme" || got.GetLogoLightUrl() != "https://acme.example/logo.svg" || got.GetOperatedBy() != "Acme Ltd" {
		t.Errorf("a good field was dropped: %+v", got)
	}
	for name, v := range map[string]string{
		"website_url": got.GetWebsiteUrl(), "support_url": got.GetSupportUrl(), "privacy_url": got.GetPrivacyUrl(),
		"accent_color": got.GetAccentColor(), "verified_host": got.GetVerifiedHost(),
	} {
		if v != "" {
			t.Errorf("%s breaks the rules and was served: %q", name, v)
		}
	}
}
