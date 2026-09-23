# Dev-only fake OIDC provider image for the auth plugin's `oauth`
# sandbox. Build locally:
#
#   docker build -t w17-fakeidp:dev plugins/auth/sandboxes/fakeidp
#
# The auth plugin's plugin.yaml references the `w17-fakeidp:dev` tag;
# codegen wires it into the consuming project's compose.w17.yaml. This
# image is NEVER shipped to production — a sandbox is throwaway dev
# infra (see docs/specs/plugins/sandbox-services.md).
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
