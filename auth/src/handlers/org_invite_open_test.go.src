package handlers

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// An OPEN invitation is an InviteToOrg with no address, and the handler treats
// the empty address as exactly that. The request's generated validation reads
// `(w17.field).blank` — so without it, the empty address is refused as
// REQUIRED_VIOLATION before the handler runs, and the open path cannot be
// reached at all. The handler tests below call the handler directly and never
// see that validation, which is how it went unnoticed (found live by
// scripts/console-auth-proof.sh). This pins the declaration the validation is
// generated from.
func TestInviteToOrg_TheAddressMayBeEmptyForAnOpenInvitation(t *testing.T) {
	fd := (&pb.InviteToOrgReq{}).ProtoReflect().Descriptor().Fields().ByName("email")
	if fd == nil {
		t.Fatal("InviteToOrgReq has no email field")
	}
	f, _ := proto.GetExtension(fd.Options(), w17pb.E_Field).(*w17pb.Field)
	if f == nil {
		t.Fatal("InviteToOrgReq.email carries no (w17.field) — the test reads the wrong descriptor")
	}
	if !f.GetBlank() {
		t.Fatal("InviteToOrgReq.email is not `blank: true`: the generated validation refuses an empty address, so an OPEN invitation cannot be created")
	}
}
