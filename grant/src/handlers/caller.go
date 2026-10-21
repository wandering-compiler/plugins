package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
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
// organization when it names one or when its caller belongs to exactly one,
// so the backoffice acts from accounts that belong to no organization.
//
// Who may call it at all is the project's endpoint ACL: the method must be in
// the deployed lock, or nobody may — without an ACL any signed-in account
// outside an organization would pass. method is the lock key without the
// activation's prefix (GRANT_SERVICE_APPROVE_ENVELOPE): the lock keys it under
// whatever name the plugin is activated as.
func (h *GrantServiceHandler) realmOnly(ctx context.Context, method string) (string, error) {
	caller, err := callerID(ctx)
	if err != nil {
		return "", err
	}
	if activeOrg(ctx) != "" {
		return "", status.Error(codes.PermissionDenied, "grant: the platform decides this, realm-wide, not from inside an organization")
	}
	if !lockHasMethod(h.Lock, method) {
		return "", status.Error(codes.PermissionDenied, "grant: the backoffice's methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return caller, nil
}

// lockHasMethod reports whether the lock allocates a permission for a method
// of this plugin, whatever the activation is named: method is the key's tail
// after the activation's prefix.
func lockHasMethod(l *acllock.Lock, method string) bool {
	if l == nil {
		return false
	}
	for k := range l.Permissions {
		if strings.HasSuffix(k, "_"+method) {
			return true
		}
	}
	return false
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
