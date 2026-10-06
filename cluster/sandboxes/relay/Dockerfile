# Relay image. Build from the PLUGIN directory, because the relay is part of
# the plugin's Go module and shares its generated pb with the handlers — one
# copy of the contract, so the two sides cannot drift:
#
#   docker build -f plugins/cluster/sandboxes/relay/Dockerfile \
#     -t ${W17_WORKSPACE:-w17}-w17-cluster-relay:dev plugins/cluster
#
# The tag is WORKSPACE-PREFIXED. An image tag is build output, and a fixed one
# on a shared docker daemon is a name every checkout overwrites.
#
# Unlike the auth plugin's fakeidp this is NOT a throwaway fake: the same image
# is what an operator runs in production, deployed separately (a relay lives
# outside the project's own network by design — it is what the workers reach).
# w17 never generates a production deploy stage for it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY src/ .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /relay ./cmd/relay

FROM alpine:3.23
RUN adduser -D -u 10001 relay
USER relay
COPY --from=build /relay /usr/local/bin/relay
# The MANAGEMENT port. The proxy port a worker and a caller use is separate and
# is published by whoever deploys this; it is not fixed here because a relay
# is told its externally visible address rather than choosing one.
EXPOSE 13444
ENTRYPOINT ["/usr/local/bin/relay"]
