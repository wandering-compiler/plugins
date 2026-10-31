package auth_test

import (
	"context"

	"filippo.io/age"
	"testing"

	"google.golang.org/grpc"

	auth "github.com/wandering-compiler/plugins/auth"
	"github.com/wandering-compiler/plugins/auth/gen"
	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
)

// testRecipient is a mailer's age recipient: a configuration that boots
// outside W17_ENV=dev names one (delivery_recipient).
var testRecipient = func() string {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	return id.Recipient().String()
}()

// Smoke test for the v4 entry contract. Without it,
// `RegisterPlugin` would have no in-module caller — the bundle
// that invokes it is generated downstream in a consuming
// project, so neither `go build` nor `go test` would exercise
// the function body inside the plugin module. The test calls
// RegisterPlugin with the same shape the bundle codegen
// produces (a Registry impl + a ClientSet impl), then asserts
// the handler got registered + the shutdown hook queued.
//
// Plugin author tests use this same scaffolding to test the
// handlers themselves: construct fakeClientSet + fakeRegistry,
// call RegisterPlugin, then invoke the registered handler's
// methods directly via the captured impl on fakeRegistry.

type fakeRegistry struct {
	auth      pb.AuthServiceServer
	shutdowns []func(context.Context) error
}

func (r *fakeRegistry) RegisterAuthServiceServer(impl pb.AuthServiceServer) { r.auth = impl }
func (r *fakeRegistry) RegisterShutdown(fn func(ctx context.Context) error) {
	r.shutdowns = append(r.shutdowns, fn)
}

type fakeClientSet struct {
	query    pb.AuthQueryClient
	mutation pb.AuthMutationClient
}

func (s fakeClientSet) AuthQuery() pb.AuthQueryClient       { return s.query }
func (s fakeClientSet) AuthMutation() pb.AuthMutationClient { return s.mutation }

// The v4 ClientSet also carries the ACL lock + distributed-transaction
// coordinator + connection name. The smoke test never invokes them (it
// only wires the handler), so empty/nil stand-ins satisfy the interface;
// AclLock follows the documented "empty non-nil lock" contract.
func (s fakeClientSet) AclLock() *acllock.Lock { return &acllock.Lock{} }
func (s fakeClientSet) DistributedTransaction() distxpb.W17DistributedTransactionClient {
	return nil
}
func (s fakeClientSet) Connection() string { return "" }

// noopQuery / noopMutation satisfy the generated typed-client
// interfaces with do-nothing methods. The embedded interface
// supplies the methods the smoke test doesn't touch (it never
// invokes them, so the nil embed never dereferences); the
// overrides carry the standard grpc client signature
// (`opts ...grpc.CallOption`) the generated interface declares.
type noopQuery struct{ pb.AuthQueryClient }

func (noopQuery) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{}, nil
}
func (noopQuery) GetUserByTokenWithPermissions(ctx context.Context, req *pb.GetUserByTokenWithPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserByTokenWithPermissionsResp, error) {
	return &pb.GetUserByTokenWithPermissionsResp{}, nil
}

type noopMutation struct{ pb.AuthMutationClient }

func (noopMutation) CreateUser(ctx context.Context, req *pb.CreateUserReq, _ ...grpc.CallOption) (*pb.CreateUserResp, error) {
	return &pb.CreateUserResp{}, nil
}
func (noopMutation) IssueToken(ctx context.Context, req *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{}, nil
}

func TestRegisterPlugin_WiresHandlerAndShutdown(t *testing.T) {
	reg := &fakeRegistry{}
	clients := fakeClientSet{query: noopQuery{}, mutation: noopMutation{}}

	if err := auth.RegisterPlugin(&gen.EnvConfig{DeliveryRecipient: testRecipient}, reg, clients); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if reg.auth == nil {
		t.Fatal("RegisterPlugin did not register an AuthServiceServer")
	}
	if len(reg.shutdowns) != 1 {
		t.Fatalf("expected 1 shutdown hook, got %d", len(reg.shutdowns))
	}
	if err := reg.shutdowns[0](context.Background()); err != nil {
		t.Errorf("shutdown hook returned err: %v", err)
	}
}

// An unknown password_hash_algo fails the boot. Falling back to a default
// would store hashes under an algorithm the operator did not choose, and a
// typo in the setting would go unnoticed until the next change of it. Every
// supported spelling boots.
func TestRegisterPlugin_UnknownPasswordHashAlgoFailsBoot(t *testing.T) {
	for _, algo := range []string{"md5", "sha256", "Argon2id", "argon2"} {
		reg := &fakeRegistry{}
		err := auth.RegisterPlugin(&gen.EnvConfig{PasswordHashAlgo: algo}, reg, fakeClientSet{query: noopQuery{}, mutation: noopMutation{}})
		if err == nil {
			t.Errorf("password_hash_algo=%q booted", algo)
		}
		if reg.auth != nil {
			t.Errorf("password_hash_algo=%q registered a handler before failing", algo)
		}
	}
	for _, algo := range []string{"", "argon2id", "bcrypt", "scrypt", "pbkdf2", "pbkdf2-sha256"} {
		if err := auth.RegisterPlugin(&gen.EnvConfig{PasswordHashAlgo: algo, DeliveryRecipient: testRecipient}, &fakeRegistry{}, fakeClientSet{query: noopQuery{}, mutation: noopMutation{}}); err != nil {
			t.Errorf("password_hash_algo=%q refused: %v", algo, err)
		}
	}
}
