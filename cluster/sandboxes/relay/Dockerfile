# Relay image. Build from the PLUGIN directory, because the relay is part of
# the plugin's Go module and shares its generated pb with the handlers — one
# copy of the contract, so the two sides cannot drift. That pb is generated,
# never committed:
#
#   in a project   `w17ctl codegen` writes it into the vendored plugin, and
#                  the project's compose.w17.yaml builds this image from there
#                  (the sandbox's `build:` in plugin.yaml);
#   in a clone     generate it first:
#                    w17ctl plugin gen-pb cluster
#                    docker build -f cluster/sandboxes/relay/Dockerfile \
#                      -t ${W17_WORKSPACE:-w17}-w17-cluster-relay:dev cluster
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
RUN test -d gen/pb || { echo "src/gen/pb is missing: in a project run \`w17ctl codegen\`, in the plugins clone \`w17ctl plugin gen-pb cluster\`, then build again" >&2; exit 1; }
RUN CGO_ENABLED=0 go build -buildvcs=false -o /relay ./cmd/relay

FROM alpine:3.23
# The identity directory exists in the image, owned by the relay: a volume
# mounted there inherits that ownership, where one created by Docker on a
# missing path is root's and the relay cannot write its key into it.
RUN adduser -D -u 10001 relay && mkdir -p /var/lib/relay && chown relay:relay /var/lib/relay
USER relay
COPY --from=build /relay /usr/local/bin/relay
# The MANAGEMENT port. The proxy port a worker and a caller use is separate and
# is published by whoever deploys this; it is not fixed here because a relay
# is told its externally visible address rather than choosing one.
EXPOSE 13444
ENTRYPOINT ["/usr/local/bin/relay"]
