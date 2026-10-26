package handlers

import (
	"context"
	"os"
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// keepsSignInHistory marks a test store that implements RecordSignInEvent
// for real (historyMutation). Every mint path writes a SignInEvent row, and
// most of this package's fakes predate the table: they embed a nil
// AuthMutationClient, so the call would panic in tests that are about
// something else. TestMain therefore writes the history only to a store that
// says it keeps it; the tests about the history use one, through the
// production writer.
type keepsSignInHistory interface{ keepsSignInHistory() }

// keepsSignInBudget marks a test store that implements SignIn's guess
// budget (CountSignInAttempt, CountDeviceSignInAttempt,
// ResetSignInAttempts) — budgetStore. The rest predate it, as they predate
// the history, and SignIn spends no budget on them.
type keepsSignInBudget interface{ keepsSignInBudget() }

// keepsCallerGrants marks a test store that answers the caller's own grants
// (GetUserOrgPermissions, GetUserRealmWidePermissions) — callerGrantsStore.
// Under an organization's lock every ceiling re-reads them (heldUnderOrgLock),
// and the package's fakes model only the caller's resolved envelope, not the
// grants behind it: TestMain re-reads them only on a store that says it keeps
// them; the tests about the re-read use one, through the production code.
type keepsCallerGrants interface{ keepsCallerGrants() }

func TestMain(m *testing.M) {
	signInBudgetApplies = func(h *AuthServiceHandler) bool {
		_, ok := h.Mutation.(keepsSignInBudget)
		return ok
	}
	write := writeSignInEvent
	writeSignInEvent = func(ctx context.Context, h *AuthServiceHandler, row *pb.RecordSignInEventReq) error {
		if _, ok := h.Mutation.(keepsSignInHistory); !ok {
			return nil
		}
		return write(ctx, h, row)
	}
	reread := heldNow
	heldNow = func(ctx context.Context, h *AuthServiceHandler, held map[int32]bool) (map[int32]bool, error) {
		if _, ok := h.Query.(keepsCallerGrants); !ok {
			return held, nil
		}
		return reread(ctx, h, held)
	}
	os.Exit(m.Run())
}
