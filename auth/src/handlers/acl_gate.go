package handlers

import (
	"context"
	"strings"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// The deployed ACL lock's view of the call being served, for the backoffice's
// realm-wide methods (org_packages, org_hosts): each refuses unless the
// endpoint ACL gates it. Staged with every activation, since more than one
// feature reads it.

// lockHasPermissions is a lock the ACL allocated permissions in; a project
// without the ACL embeds an empty one.
func lockHasPermissions(l *acllock.Lock) bool {
	return l != nil && len(l.Permissions) > 0
}

// lockGatesCall reports whether the deployed lock allocates a permission for
// the call being served — exactly, never by a name's tail: the lock keys a
// method `<module>.<Service>.<Method>` after the project's service, which
// grpc.Method names. Called outside a gRPC server (a direct call), the
// plugin's own service name stands in; either way a method the lock does not
// name refuses.
func lockGatesCall(ctx context.Context, l *acllock.Lock, ownService, method string) bool {
	svc, m := ownService, method
	if full, ok := grpc.Method(ctx); ok {
		if i := strings.LastIndex(full, "/"); i > 0 {
			svc, m = strings.TrimPrefix(full[:i], "/"), full[i+1:]
		}
	}
	dot := strings.LastIndex(svc, ".")
	if dot < 0 {
		return false
	}
	pkg, name := svc[:dot], svc[dot+1:]
	module := pkg[strings.LastIndex(pkg, ".")+1:]
	_, ok := acllock.IDByString(l, module+"."+name+"."+m)
	return ok
}
