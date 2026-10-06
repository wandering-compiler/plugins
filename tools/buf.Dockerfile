# buf + the two Go protoc plugins, for tools/gen-pb.sh. Build: `make buf-image`.
#
# The plugins are LOCAL binaries (not `remote:` BSR plugins, which would hit the
# anonymous rate limit), pinned to exactly what the committed pb headers declare
# (protoc-gen-go v1.36.11 / protoc-gen-go-grpc v1.6.2), so a regeneration matches
# the console's in-process generator byte for byte. Bump them together with the
# w17 SDK's generator, or the output churns.

FROM golang:1.26-alpine AS plugins
ENV CGO_ENABLED=0
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 \
 && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

FROM bufbuild/buf:1.70.0
COPY --from=plugins /go/bin/protoc-gen-go      /usr/local/bin/protoc-gen-go
COPY --from=plugins /go/bin/protoc-gen-go-grpc /usr/local/bin/protoc-gen-go-grpc
