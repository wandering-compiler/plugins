package handlers

import (
	"errors"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `user_admin` feature — turnkey admin user
// management (the admin Users page + soft-disable/enable + delete). It is
// staged into a bundle ONLY when the activation enables `user_admin`
// (plugin.yaml maps the feature to this file via go_files). With the
// feature off it is not staged, so the sign-in disabled gate keeps its
// no-op default and `User.disabled_at` isn't emitted. Standalone (the
// plugin author's own `go test`) always compiles it, since gating happens
// at activation staging, not in the source tree.

// errAuthnUserDisabled is the internal cause behind the opaque
// Unauthenticated a disabled account gets on SignIn. Never surfaced to
// the caller (SignIn maps every failure to the same opaque code) — it
// exists for logs / tests.
var errAuthnUserDisabled = errors.New("account disabled")

// init wires the disabled-account gate on package load. `disabled_at`
// exists on the User message only when `user_admin` is active (this file
// is staged), so naming it via GetDisabledAt() is safe to compile here.
func init() {
	signInDisabledGate = func(user *pb.User) error {
		if user.GetDisabledAt() != nil {
			return errAuthnUserDisabled
		}
		return nil
	}
}
