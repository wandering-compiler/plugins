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
# Unlike the auth plugin's fakeidp this is NOT a throwaway fake: it builds the
# relay binary production runs. A w17 deploy target builds that binary from
# the plugin's deploy block (deploy/plugins/relay/Dockerfile in the rendered
# stack) and mints its identities at deploy time. A hand-written stack may run
# THIS image in production: mount a volume at /var/lib/relay, mint the
# identities into it with `relay mint` / `relay issue-worker`, and pass them
# with --cert/--key/--ca-cert/--ca-key (SPEC.md, "Running the relay in
# production"). What makes the sandbox dev-only is its wiring — an identity
# minted inside the container and lost on `down` — not the image.
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
