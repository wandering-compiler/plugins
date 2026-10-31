package sealing

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestSeal_OnlyTheIdentityOpensIt(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	s, err := Seal(" "+id.Recipient().String()+"\n", "reset-token-42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "reset-token-42") {
		t.Fatal("the sealed value carries the credential")
	}
	ct, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not standard base64: %v", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r); string(b) != "reset-token-42" {
		t.Fatalf("opened %q", b)
	}
	if _, err := age.Decrypt(bytes.NewReader(ct), other); err == nil {
		t.Fatal("another identity opened it")
	}
	if again, _ := Seal(id.Recipient().String(), "reset-token-42"); again == s {
		t.Fatal("two seals of one value are equal")
	}
}

func TestSeal_RefusesWhatIsNoRecipient(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for _, r := range []string{"", "age1nope", id.String()} {
		if _, err := Seal(r, "x"); err == nil {
			t.Errorf("Seal(%q) sealed", r)
		}
		if CheckRecipient(r) == nil {
			t.Errorf("CheckRecipient(%q) accepted", r)
		}
	}
	if err := CheckRecipient(id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
}
