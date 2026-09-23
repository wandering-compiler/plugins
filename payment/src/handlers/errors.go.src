package handlers

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// Storage constraint-violation detail codes (srcgo/lib/validation
// defaults). Every DB constraint violation surfaces as a
// codes.InvalidArgument gRPC status carrying a w17.ErrorDetail; the
// specific kind lives in ErrorDetail.code, NOT the top-level code.
const (
	codeUniqueViolation = "UNIQUE_VIOLATION" // duplicate key (PK / unique)
	codeInvalidValue    = "INVALID_VALUE"    // FK / CHECK constraint
)

// constraintCode returns the w17 ErrorDetail.code carried by a storage
// constraint-violation error, or "" if err is not one. This is the
// caller's only reliable discriminator — the top-level gRPC code is a
// uniform InvalidArgument across unique / FK / check.
func constraintCode(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return ""
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed.GetCode()
		}
	}
	return ""
}

// invalidArg returns a codes.InvalidArgument status for a caller-input
// failure (missing required field, etc.).
func invalidArg(msg string) error {
	return status.Error(codes.InvalidArgument, msg)
}

// notFound returns a codes.NotFound status.
func notFound(msg string) error {
	return status.Error(codes.NotFound, msg)
}

// providerFailure wraps a backend/provider error as codes.Unavailable —
// the provider call failed (network, API error); the caller may retry.
// The cause is preserved for handler-side logging via %w.
func providerFailure(cause error) error {
	return status.Errorf(codes.Unavailable, "payment provider error: %v", cause)
}
