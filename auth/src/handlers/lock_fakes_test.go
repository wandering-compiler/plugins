package handlers

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The organization's row lock (withOrgLock) on the query fakes whose tests
// reach a change to who holds what in an organization: a fake has no rows to
// lock, and answers for the organization it was asked about.

func (*botAdminMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*inviteMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*inviteTokenMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*mintMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*orgRolesMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*hostMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*prodMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (*roleCatalogueMock) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}

func (botTokenQuery) LockOrganization(_ context.Context, in *pb.LockOrganizationReq, _ ...grpc.CallOption) (*pb.LockOrganizationResp, error) {
	return &pb.LockOrganizationResp{OrgId: in.GetOrgId()}, nil
}
