package handlers

import (
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// isUniqueViolation reports whether a storage error is a duplicate key: w17
// collapses it to InvalidArgument with an ErrorDetail coded UNIQUE_VIOLATION.
func isUniqueViolation(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok && ed.GetCode() == "UNIQUE_VIOLATION" {
			return true
		}
	}
	return false
}
