package handlers

import (
	"context"
	"encoding/base64"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// The caller of a request, and whose billing it may touch.
//
// The gateway threads the verified auth response, marshaled, to every
// handler under `x-w17-user`, and w17 fixes the caller's id at field 2 of it
// (`string user_id = 2` is required of every auth method's response). The
// plugin cannot name the project's AuthResp type, so it reads that one field
// straight off the wire.
//
// Two kinds of request reach these handlers:
//
//   - on behalf of a signed-in person: the envelope is there, and the
//     request may act only for that person;
//   - from the project's own code with no person behind it (a job, a
//     webhook, an event subscriber): no envelope, and the request names the
//     user it acts for.
//
// The gateway strips any client-sent `x-w17-*` metadata before it stamps its
// own, so a client cannot pass for the second kind or forge the first.
//
// The envelope follows the request: a project handler that calls
// PaymentService while serving a signed-in person (in process or over a
// dialled conn, both relay `x-w17-user`) calls it AS that person. Code that
// deliberately acts for someone else there (an admin action, an owner paying
// for a member) removes `x-w17-user` from its incoming metadata first; see
// the README's "Who a request acts for".

const callerMetadataKey = "x-w17-user"

var errNoCaller = errors.New("payment: request carries no authenticated caller")

// callerID returns the signed-in caller's id, and whether the request came
// through the gateway at all. An envelope that is present but carries no
// readable id is an error, never "no caller": a broken envelope must not
// turn a person's request into a trusted internal one.
func callerID(ctx context.Context) (id string, viaGateway bool, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false, nil
	}
	vals := md.Get(callerMetadataKey)
	if len(vals) == 0 {
		return "", false, nil
	}
	// The gateway stamps exactly one non-empty value. An empty or repeated
	// one is a broken envelope, never "no caller".
	if len(vals) != 1 || vals[0] == "" {
		return "", true, errNoCaller
	}
	raw, err := base64.StdEncoding.DecodeString(vals[0])
	if err != nil {
		return "", true, errNoCaller
	}
	id = userIDField(raw)
	if id == "" {
		return "", true, errNoCaller
	}
	return id, true, nil
}

// userIDField reads field 2 (a length-delimited string) from a marshaled
// message; the last occurrence wins, as in proto decoding. "" when absent
// or malformed.
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

// actingFor resolves the user a request may act for. Through the gateway it
// is the caller: an empty `user_id` means the caller, and any other id is
// refused. From the project's own code, it is the `user_id` the request
// names.
func actingFor(ctx context.Context, requested string) (string, error) {
	caller, viaGateway, err := callerID(ctx)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	if !viaGateway {
		return requested, nil
	}
	if requested != "" && requested != caller {
		return "", status.Error(codes.PermissionDenied, "payment: a signed-in caller may act only on their own billing")
	}
	return caller, nil
}

// signedInCaller is the caller of an endpoint that only reads the caller's
// own data: it requires the gateway's envelope.
func signedInCaller(ctx context.Context) (string, error) {
	caller, viaGateway, err := callerID(ctx)
	if err != nil || !viaGateway {
		return "", status.Error(codes.Unauthenticated, errNoCaller.Error())
	}
	return caller, nil
}

// errNotYours is how a read of someone else's row answers: as if it did not
// exist, so ids cannot be probed for other people's billing.
const errNotYours = "not found"

// callerCustomerID is the signed-in caller's customer id. A caller who is
// not a customer yet owns nothing, so it answers NotFound like a row that is
// not theirs.
func (h *PaymentServiceHandler) callerCustomerID(ctx context.Context) (string, error) {
	caller, err := signedInCaller(ctx)
	if err != nil {
		return "", err
	}
	got, err := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: caller})
	if err != nil {
		if absent(err) {
			return "", notFound(errNotYours)
		}
		return "", err
	}
	if id := got.GetCustomer().GetId(); id != "" {
		return id, nil
	}
	return "", notFound(errNotYours)
}

// ownRow maps a storage read of one row to the caller's view of it: absent,
// or another customer's, both answer NotFound.
func ownRow(readErr error, owner, customer string) error {
	if readErr != nil {
		if absent(readErr) {
			return notFound(errNotYours)
		}
		return readErr
	}
	if owner != customer {
		return notFound(errNotYours)
	}
	return nil
}

// GetMyPayment returns one of the caller's payments. Another customer's
// payment answers NotFound.
func (h *PaymentServiceHandler) GetMyPayment(ctx context.Context, req *pb.GetMyPaymentReq) (*pb.GetPaymentResp, error) {
	customer, err := h.callerCustomerID(ctx)
	if err != nil {
		return nil, err
	}
	got, err := h.Query.GetPayment(ctx, &pb.GetPaymentReq{Id: req.GetId()})
	if err := ownRow(err, got.GetPayment().GetCustomerId(), customer); err != nil {
		return nil, err
	}
	return got, nil
}
