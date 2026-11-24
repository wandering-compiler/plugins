package handlers

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"

	"github.com/wandering-compiler/sdk/go/core/grpcerr"
)

// The codes a client branches on, beside the sentences a person reads. Only
// the backoffice's actions answer with them: the relay and worker wire, and a
// service reserving work, are machines and keep the operator's text.
const (
	CodeSelectOneRelay = "SELECT_ONE_RELAY"
	CodeRelayNotFound  = "RELAY_NOT_FOUND"
	CodeSelectWorker   = "SELECT_WORKER"
	CodeWorkerNotFound = "WORKER_NOT_FOUND"
)

// The sentences an operator reads in the backoffice when the cluster plugin
// refuses an action. Each is a msgid: plugin.yaml mirrors this set (make
// plugin-msgids-sync) so a project's catalogs carry them for translation.
//
//w17:msgid
const (
	MsgSelectOneRelay = "Select exactly one relay to issue a registration code for."
	MsgRelayNotFound  = "That relay is no longer registered. Refresh the list and select again."
	MsgSelectWorker   = "Select at least one worker."
	MsgWorkerNotFound = "A selected worker is no longer registered, so nothing was changed. Refresh the list and select again."
)

// relayNotFound refuses an action on a relay the registry no longer holds.
func relayNotFound(ctx context.Context, method, id string) error {
	return grpcerr.ForUser(ctx, codes.NotFound, method,
		fmt.Sprintf("cluster: no relay %q is registered", id), CodeRelayNotFound, MsgRelayNotFound)
}
