# Dev-only fake OIDC provider image for the auth plugin's `oauth`
# sandbox. Build locally:
#
#   docker build -t ${W17_WORKSPACE:-w17}-w17-fakeidp:dev auth/sandboxes/fakeidp   (from a clone of this repository)
#
# The auth plugin's plugin.yaml references the `${W17_WORKSPACE:-w17}-w17-fakeidp:dev` tag;
# codegen wires it into the consuming project's compose.w17.yaml. This
# image is NEVER shipped to production — a sandbox is throwaway dev
# infra, started only by a project's dev compose.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /fakeidp .

FROM alpine:3.23
RUN adduser -D -u 10001 fakeidp
USER fakeidp
COPY --from=build /fakeidp /usr/local/bin/fakeidp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fakeidp"]
