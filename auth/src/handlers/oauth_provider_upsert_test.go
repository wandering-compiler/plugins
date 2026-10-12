package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// UpsertOAuthProvider is how a project configures a provider from its own
// environment. Both of its branches, the insert and the update, must write
// the secret to the encrypted column and clear the plaintext legacy one: a
// rewrite that kept the old plaintext would leave a secret readable in the
// table after the operator moved it to the environment. Storage encrypts
// what the request's CRYPTED_SECRET field carries, so the request field is
// held to that type too. The in-memory fakes here encrypt nothing; this
// reads the declaration instead.
func TestUpsertOAuthProvider_WritesTheSecretEncryptedOnBothBranches(t *testing.T) {
	src, err := os.ReadFile("../../proto/mutations/auth_mutation.proto")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "rpc UpsertOAuthProvider(")
	if start < 0 {
		t.Fatal("UpsertOAuthProvider not found in auth_mutation.proto")
	}
	end := strings.Index(s[start:], "\n  }\n")
	if end < 0 {
		t.Fatal("end of UpsertOAuthProvider not found")
	}
	dql := strings.Join(regexp.MustCompile(`"([^"]*)"`).FindAllString(s[start:start+end], -1), "")
	insert, update, found := strings.Cut(dql, "ON CONFLICT (name) DO UPDATE SET")
	if !found {
		t.Fatalf("UpsertOAuthProvider is not an upsert on name:\n%s", dql)
	}
	for branch, part := range map[string]string{"insert": insert, "update": update} {
		if !strings.Contains(part, "secret = :secret") {
			t.Errorf("the %s branch does not write the secret:\n%s", branch, part)
		}
		if !strings.Contains(part, "client_secret = NULL") {
			t.Errorf("the %s branch keeps the plaintext legacy secret:\n%s", branch, part)
		}
	}
	if !regexp.MustCompile(`(?s)message UpsertOAuthProviderReq \{.*?string secret\s*=\s*\d+\s*\[\(w17\.field\) = \{ type: CRYPTED_SECRET \}\]`).MatchString(s) {
		t.Error("UpsertOAuthProviderReq.secret is not a CRYPTED_SECRET field, so storage would not encrypt it")
	}
}
