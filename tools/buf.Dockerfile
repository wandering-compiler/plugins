# buf + the two Go protoc plugins, for the committed pb that a directory with
# its own buf.gen.yaml generates (`make check-committed-pb`). Build: `make
# buf-image`. A plugin's src/gen is not this image's business: `make gen` asks
# the console.
#
# The plugins are LOCAL binaries (not `remote:` BSR plugins, which would hit the
# anonymous rate limit), pinned to exactly what the committed pb headers declare
# (protoc-gen-go v1.36.11 / protoc-gen-go-grpc v1.6.2), so a regeneration matches
# byte for byte. Bump them together with the committed pb, or the output churns.

FROM golang:1.26-alpine AS plugins
ENV CGO_ENABLED=0
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 \
 && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

FROM bufbuild/buf:1.70.0
COPY --from=plugins /go/bin/protoc-gen-go      /usr/local/bin/protoc-gen-go
COPY --from=plugins /go/bin/protoc-gen-go-grpc /usr/local/bin/protoc-gen-go-grpc
