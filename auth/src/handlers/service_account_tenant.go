package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// This file exists only when BOTH `service_account` and `tenant_scope` are on
// (plugin.yaml, `go_files_combined`). It is the reason the pair stopped being
// declared incompatible: under tenant_scope `User.tenant_id` is NOT NULL, and
// a machine account created without one was refused at runtime, on every call.
//
// Neither feature's own file can write the field. CreateBotUserReq.tenant_id
// is in the pb only with tenant_scope, and service_account.go is staged with
// service_account alone — naming the field there would stop the bundle
// compiling for every activation without tenant_scope.
func init() {
	botUserFillers = append(botUserFillers, fillBotTenant)
}

// errNoActiveTenant is the refusal when the operator has no tenant scope —
// a principal resolved without one, which tenant_scope's own decorator only
// produces for an account that has no tenant row to read.
var errNoActiveTenant = errors.New("no tenant in scope — a machine account is created inside the tenant its operator is acting in")

// fillBotTenant puts the machine account into the tenant the operator is
// acting in.
//
// The tenant comes from the CALLER's authenticated scope (stamped by
// resolveTenantScope), never from the request, for the same reason CreateBot
// takes the organization from the active scope: an id off the wire would let
// an operator provision a bot into a tenant they are not in.
func fillBotTenant(ctx context.Context, req *pb.CreateBotUserReq) error {
	tenantID, ok := principal.Scope(ctx, "tenant_id")
	if !ok || tenantID == "" {
		return status.Error(codes.FailedPrecondition, errNoActiveTenant.Error())
	}
	req.TenantId = tenantID
	return nil
}
