package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/grant/gen/pb"
)

// Who calls, and where they act.
//
// The gateway threads the verified auth response, marshaled, under
// `x-w17-user` (the caller's id is field 2 of every auth method's response),
// and the organization the auth plugin resolved as `x-w17-scope-org_id`. A
// client's own `x-w17-*` metadata never reaches a handler: the gateway
// strips it before stamping its own.

const callerMetadataKey = "x-w17-user"

var errNoCaller = errors.New("grant: request carries no authenticated caller")

// callerID is the signed-in caller's id. A missing or broken envelope is
// Unauthenticated. Read off the envelope's field 2 here rather than with
// principal.UserID, which needs the project's AuthResp type — a plugin
// compiles alone and cannot name it (the payment plugin reads it the same way).
func callerID(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get(callerMetadataKey)
	if len(vals) != 1 || vals[0] == "" {
		return "", status.Error(codes.Unauthenticated, errNoCaller.Error())
	}
	raw, err := base64.StdEncoding.DecodeString(vals[0])
	if err != nil {
		return "", status.Error(codes.Unauthenticated, errNoCaller.Error())
	}
	id := userIDField(raw)
	if id == "" {
		return "", status.Error(codes.Unauthenticated, errNoCaller.Error())
	}
	return id, nil
}

// userIDField reads field 2 (a length-delimited string) from a marshaled
// message; the last occurrence wins, as in proto decoding.
func userIDField(b []byte) string {
	var id string
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return ""
		}
		b = b[n:]
		if num == 2 && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return ""
			}
			id = string(v)
			b = b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return ""
		}
		b = b[m:]
	}
	return id
}

// activeOrg is the organization the request acts in, "" when it acts in
// none (realm-wide).
func activeOrg(ctx context.Context) string {
	org, _ := principal.Scope(ctx, "org_id")
	return org
}

// heldRealmWide: the request's credential holds the call being served
// realm-wide while it acts inside an organization — the backoffice, also a
// member there. The auth plugin's Authenticate sets realm_permissions (`*`
// for a realm-wide wildcard, else the permission ids its realm-wide roles
// grant); the gateway writes it.
func (h *GrantServiceHandler) heldRealmWide(ctx context.Context, method string) bool {
	v, _ := principal.Scope(ctx, "realm_permissions")
	if v == "*" {
		return true
	}
	if v == "" {
		return false
	}
	id, ok := lockIDOfCall(ctx, h.Lock, pb.GrantService_ServiceDesc.ServiceName, method)
	if !ok {
		return false
	}
	return slices.Contains(strings.Split(v, ","), strconv.Itoa(id))
}

// inOrg is the caller and the organization they act in; refused when the
// request acts in none.
func inOrg(ctx context.Context) (caller, orgID string, err error) {
	if caller, err = callerID(ctx); err != nil {
		return "", "", err
	}
	if orgID = activeOrg(ctx); orgID == "" {
		return "", "", status.Error(codes.FailedPrecondition, "grant: this acts in an organization — name one (W17-Org)")
	}
	return caller, orgID, nil
}

// realmOnly is the backoffice caller; refused when the request acts inside an
// organization, whatever roles its admins hold — an organization does not
// approve its own envelope or bind its own hosts. A request acts in an
// organization when it names one or when its caller belongs to exactly one;
// the backoffice may be a member somewhere, so a request whose credential
// holds the method realm-wide (the auth plugin's realm_permissions scope) is
// the backoffice's wherever it acts.
//
// Who may call it at all is the project's endpoint ACL: the method must be in
// the deployed lock, or nobody may — without an ACL any signed-in account
// outside an organization would pass. method is the RPC's name (lockGatesCall
// finds its key).
func (h *GrantServiceHandler) realmOnly(ctx context.Context, method string) (string, error) {
	caller, err := callerID(ctx)
	if err != nil {
		return "", err
	}
	if activeOrg(ctx) != "" && !h.heldRealmWide(ctx, method) {
		return "", status.Error(codes.PermissionDenied, "grant: the platform decides this, realm-wide, not from inside an organization")
	}
	if !lockGatesCall(ctx, h.Lock, pb.GrantService_ServiceDesc.ServiceName, method) {
		return "", status.Error(codes.PermissionDenied, "grant: the backoffice's methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return caller, nil
}

// lockGatesCall reports whether the deployed lock allocates a permission for
// the call being served — exactly, never by a name's tail: the lock keys a
// method `<module>.<Service>.<Method>` after the project's service, which
// grpc.Method names. Called outside a gRPC server (a direct call), the
// plugin's own service name stands in; either way a method the lock does not
// name refuses.
func lockGatesCall(ctx context.Context, l *acllock.Lock, ownService, method string) bool {
	_, ok := lockIDOfCall(ctx, l, ownService, method)
	return ok
}

// lockIDOfCall is the permission the deployed lock allocates for the call
// being served, found as lockGatesCall finds it.
func lockIDOfCall(ctx context.Context, l *acllock.Lock, ownService, method string) (int, bool) {
	svc, m := ownService, method
	if full, ok := grpc.Method(ctx); ok {
		if i := strings.LastIndex(full, "/"); i > 0 {
			svc, m = strings.TrimPrefix(full[:i], "/"), full[i+1:]
		}
	}
	dot := strings.LastIndex(svc, ".")
	if dot < 0 {
		return 0, false
	}
	pkg, name := svc[:dot], svc[dot+1:]
	module := pkg[strings.LastIndex(pkg, ".")+1:]
	return acllock.IDByString(l, module+"."+name+"."+m)
}

// isUniqueConflict is a write refused by a unique index: storage reports it as
// InvalidArgument with an ErrorDetail{code: UNIQUE_VIOLATION} (or
// AlreadyExists).
func isUniqueConflict(err error) bool {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return false
	}
	if st.Code() == codes.AlreadyExists {
		return true
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok && ed.GetCode() == "UNIQUE_VIOLATION" {
			return true
		}
	}
	return false
}
