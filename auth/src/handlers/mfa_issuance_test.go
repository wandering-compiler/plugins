package handlers

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// a consumer — the five-attempt lockout is PER CHALLENGE, and a challenge is
// minted on every password sign-in. An attacker who already holds the
// password (the exact threat a second factor exists for) buys five more
// guesses per sign-in, forever: the bound on one challenge bounds nothing
// about the total. These tests pin the two halves that close it — a cap on
// issuance, and superseding so only one code is ever live.

func (m *mfaMock) CountRecentMfaChallenges(ctx context.Context, in *pb.CountRecentMfaChallengesReq, _ ...grpc.CallOption) (*pb.CountRecentMfaChallengesResp, error) {
	m.countedSince = in.GetSince()
	if m.countErr != nil {
		return nil, m.countErr
	}
	return &pb.CountRecentMfaChallengesResp{Count: m.challengeCount}, nil
}

// The base mock has no serialisation to model — the concurrency case uses
// lockingIssuanceMock below, which does. Here it only has to EXIST, because
// issuance now takes the lock on every path.
func (m *mfaMock) LockUserForIssuance(ctx context.Context, in *pb.LockUserForIssuanceReq, _ ...grpc.CallOption) (*pb.LockUserForIssuanceResp, error) {
	m.ops = append(m.ops, "lock:"+in.GetUserId())
	return &pb.LockUserForIssuanceResp{UserId: in.GetUserId()}, nil
}

func (m *mfaMock) SupersedePendingMfaChallenges(ctx context.Context, in *pb.SupersedePendingMfaChallengesReq, _ ...grpc.CallOption) (*pb.SupersedePendingMfaChallengesResp, error) {
	m.ops = append(m.ops, "supersede:"+in.GetUserId())
	if m.supersedeErr != nil {
		return nil, m.supersedeErr
	}
	return &pb.SupersedePendingMfaChallengesResp{}, nil
}

func gateUser() *pb.User { return &pb.User{Id: "u1", Email: "a@b.c"} }

// The cap refuses BEFORE a challenge exists — which is also what stops the
// message going out, since the challenge insert is what emits
// MfaChallengeRequested.
func TestMfaIssuance_CapRefusesOnceTheWindowIsSpent(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.MaxMfaChallengesPerWindow = 3

	m.challengeCount = 3
	resp, challenged, err := mfaSignInGate(context.Background(), h, gateUser(), "", false)
	if err == nil {
		t.Fatalf("the %dth challenge in the window was issued — the cap is not enforced (resp=%v challenged=%v)",
			m.challengeCount+1, resp, challenged)
	}
	if m.createdChallenge != nil {
		t.Error("a challenge row was written despite the refusal — the code went out anyway")
	}

	// And one under the cap still works, so the test is not passing because
	// the gate refuses everything.
	m.challengeCount = 2
	if _, ok, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err != nil || !ok {
		t.Fatalf("a sign-in inside the budget was refused: ok=%v err=%v", ok, err)
	}
}

// The refusal is reachable ONLY after the password verified, so it may say
// what happened. Folding it into the opaque answer would tell a user whose
// password is fine that their password is wrong — a consumer's complaint,
// one flow over.
func TestMfaIssuance_CapRefusalIsNotInvalidCredentials(t *testing.T) {
	st, ok := status.FromError(Unauthenticated(errMfaChallengeBudget))
	if !ok {
		t.Fatal("the budget refusal carries no wire status")
	}
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("budget refusal went out as %s, want ResourceExhausted", st.Code())
	}
	if st.Message() == authnErrorMessage {
		t.Errorf("budget refusal says %q — it sends a user with a working password to reset it", st.Message())
	}
	if !strings.Contains(st.Message(), "too many") {
		t.Errorf("budget refusal message does not say what happened: %q", st.Message())
	}

	// The exception must stay narrow: an ordinary refusal is still opaque,
	// and a status error arriving from SOMETHING ELSE must not be able to
	// pick the wire answer.
	if st, _ := status.FromError(Unauthenticated(errMfaChallengeInvalid)); st.Code() != codes.Unauthenticated {
		t.Errorf("an ordinary refusal went out as %s — the opaque contract is broken", st.Code())
	}
	downstream := status.Error(codes.ResourceExhausted, "some other service is rate limited")
	if st, _ := status.FromError(Unauthenticated(downstream)); st.Message() == "some other service is rate limited" {
		t.Error("a downstream status steered the wire answer — deliberateStatus is classifying on the code, not on our own type")
	}
}

// A counter that cannot answer must refuse. Issuing on a failed count is
// the same as having no cap during an outage — which is when an attacker
// would like it least enforced.
func TestMfaIssuance_CapFailsClosedWhenTheCountIsUnreadable(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", countErr: status.Error(codes.Unavailable, "counter down")}
	h := newMfaHandler(m)

	if _, _, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err == nil {
		t.Fatal("an unreadable count issued a challenge anyway — the cap is open during an outage")
	}
	if m.createdChallenge != nil {
		t.Error("a challenge was written despite the unreadable count")
	}
}

// The window is the knob's, not a constant baked at the call site.
func TestMfaIssuance_CountsOverTheConfiguredWindow(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.MfaChallengeWindowSeconds = 60

	if _, _, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err != nil {
		t.Fatalf("gate: %v", err)
	}
	if m.countedSince == nil {
		t.Fatal("the handler asked for no window at all")
	}
	if age := time.Since(m.countedSince.AsTime()); age < 55*time.Second || age > 65*time.Second {
		t.Errorf("counted over a %s window, want ~60s — the knob is not reaching the query", age)
	}

	// Unset → the default, not a zero window (which would count nothing and
	// make the cap unreachable).
	h.MfaChallengeWindowSeconds = 0
	if _, _, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err != nil {
		t.Fatalf("gate: %v", err)
	}
	if age := time.Since(m.countedSince.AsTime()); age < time.Duration(defaultMfaChallengeWindowSeconds-30)*time.Second {
		t.Errorf("an unset window counted over %s — a zero window counts nothing and the cap never trips", age)
	}
}

// Superseding is what makes "one live code" true. Without it N sign-ins
// leave N codes valid at once, each with its own budget — and a user who
// clicks sign-in five times holds five working codes.
func TestMfaIssuance_NewChallengeRetiresThePendingOnes(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)

	if _, _, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err != nil {
		t.Fatalf("gate: %v", err)
	}
	want := []string{"lock:u1", "supersede:u1", "create"}
	if len(m.ops) != len(want) {
		t.Fatalf("issuance performed %v, want %v", m.ops, want)
	}
	for i := range want {
		if m.ops[i] != want[i] {
			t.Fatalf("issuance performed %v, want %v — the previous code stays live, or is retired after the new one", m.ops, want)
		}
	}
}

// The pair is a replacement, not two independent writes: a create that
// fails after the supersede leaves the user with no code at all, from an
// operation whose whole job was to hand them one.
func TestMfaIssuance_SupersedeAndCreateAreOneSeam(t *testing.T) {
	src, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatalf("read mfa.go: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "func mfaSignInGate(")
	if i < 0 {
		t.Fatal("mfaSignInGate not found")
	}
	gate := body[i : i+strings.Index(body[i:], "\n}\n")]
	if strings.Contains(gate, "h.Mutation.CreateMfaChallenge(") {
		t.Error("mfaSignInGate writes the challenge directly — the supersede is separable again")
	}
	if !strings.Contains(gate, "h.issueMfaChallenge(") {
		t.Error("mfaSignInGate no longer goes through issueMfaChallenge — nothing holds the pair together")
	}
	j := strings.Index(body, "func (h *AuthServiceHandler) issueMfaChallenge(")
	if j < 0 {
		t.Fatal("issueMfaChallenge not found")
	}
	seam := body[j : j+strings.Index(body[j:], "\n}\n")]
	if !strings.Contains(seam, "distx.Begin(") {
		t.Error("issueMfaChallenge opens no transaction — the seam exists but nothing wraps it")
	}
	if !strings.Contains(seam, "Rollback(") {
		t.Error("issueMfaChallenge never rolls back — a failed create commits the supersede on its own")
	}
}

// A failed supersede must not mint a challenge either: issuing one anyway
// would be the un-capped behaviour, reachable by whatever broke the update.
func TestMfaIssuance_AFailedSupersedeMintsNothing(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", supersedeErr: errors.New("update refused")}
	h := newMfaHandler(m)

	if _, _, err := mfaSignInGate(context.Background(), h, gateUser(), "", false); err == nil {
		t.Fatal("a failed supersede still issued a challenge — older codes stay live beside the new one")
	}
	if m.createdChallenge != nil {
		t.Error("a challenge was created after the supersede failed")
	}
}

// The per-challenge budget and the issuance cap are two halves and the
// comment on maxMfaAttempts used to name the escape ("the user restarts the
// sign-in flow for a fresh challenge") as if it were fine. Keep them read as
// a pair: a reader who takes either for the whole bound draws a consumer again.
func TestMfaIssuance_AttemptCeilingDoesNotClaimToBoundGuessing(t *testing.T) {
	src, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatalf("read mfa.go: %v", err)
	}
	i := strings.Index(string(src), "maxMfaAttempts = 5")
	if i < 0 {
		t.Fatal("maxMfaAttempts not found")
	}
	doc := string(src)[:i]
	if !strings.Contains(doc, "ISSUANCE cap") {
		t.Error("maxMfaAttempts is documented without naming the issuance cap — it reads as the whole bound, and it is half of one")
	}
}

var _ = timestamppb.Now

// a consumer — the cap counted outside any transaction and then decided, which
// bounds nothing against anything concurrent. They measured it: twenty
// sign-ins at once produced twenty challenges past a limit of ten, because
// all twenty read zero before any of them committed. An attacker who already
// holds the password sends twenty at once as easily as twenty in a row.
//
// My own tests missed it because every one of them was SERIAL. A serial test
// of a read-then-decide cap passes by construction.
//
// The mock stands in for the database's serialisation the way mfaMock's mutex
// stands in for RecordMfaAttempt's atomic UPDATE: LockUserForIssuance holds a
// per-user lock for the rest of the "transaction", so what this exercises is
// whether the HANDLER does its counting inside that section.
type lockingIssuanceMock struct {
	*mfaMock
	mu       sync.Mutex
	held     bool
	issued   int
	locked   int
	unlocked int
}

func (m *lockingIssuanceMock) LockUserForIssuance(ctx context.Context, in *pb.LockUserForIssuanceReq, _ ...grpc.CallOption) (*pb.LockUserForIssuanceResp, error) {
	m.mu.Lock()
	m.locked++
	m.held = true
	return &pb.LockUserForIssuanceResp{UserId: in.GetUserId()}, nil
}

// release is what a COMMIT/ROLLBACK does to the row lock.
func (m *lockingIssuanceMock) release() {
	if m.held {
		m.held = false
		m.unlocked++
		m.mu.Unlock()
	}
}

func (m *lockingIssuanceMock) CountRecentMfaChallenges(ctx context.Context, in *pb.CountRecentMfaChallengesReq, _ ...grpc.CallOption) (*pb.CountRecentMfaChallengesResp, error) {
	if !m.held {
		// The count ran outside the serialised section — the defect itself.
		return nil, errors.New("counted without holding the issuance lock")
	}
	return &pb.CountRecentMfaChallengesResp{Count: int64(m.issued)}, nil
}

func (m *lockingIssuanceMock) SupersedePendingMfaChallenges(ctx context.Context, in *pb.SupersedePendingMfaChallengesReq, _ ...grpc.CallOption) (*pb.SupersedePendingMfaChallengesResp, error) {
	return &pb.SupersedePendingMfaChallengesResp{}, nil
}

func (m *lockingIssuanceMock) CreateMfaChallenge(ctx context.Context, in *pb.CreateMfaChallengeReq, _ ...grpc.CallOption) (*pb.CreateMfaChallengeResp, error) {
	m.issued++
	defer m.release() // commit
	return &pb.CreateMfaChallengeResp{Challenge: &pb.MfaChallenge{Id: "ch", UserId: in.GetUserId()}}, nil
}

func TestMfaIssuance_CapHoldsUnderConcurrency(t *testing.T) {
	const cap, callers = 10, 40
	m := &lockingIssuanceMock{mfaMock: &mfaMock{userEmail: "a@b.c"}}
	h := newMfaHandler(m.mfaMock)
	h.Query, h.Mutation = m, m
	h.MaxMfaChallengesPerWindow = cap

	var wg sync.WaitGroup
	var granted int64
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := mfaSignInGate(context.Background(), h, gateUser(), "", false)
			if err != nil {
				m.release() // refused inside the section: rollback
				return
			}
			if ok {
				atomic.AddInt64(&granted, 1)
			}
		}()
	}
	wg.Wait()

	if m.issued > cap {
		t.Errorf("%d challenges were issued against a cap of %d — the count and the insert are not one serialised section",
			m.issued, cap)
	}
	if got := atomic.LoadInt64(&granted); int(got) != m.issued {
		t.Errorf("%d callers were told yes but %d challenges exist", got, m.issued)
	}
	if m.issued == 0 {
		t.Fatal("nothing was issued at all — this test is not exercising the path")
	}
}

func (m *lockingIssuanceMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId()}}, nil
}
