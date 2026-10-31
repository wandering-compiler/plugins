# Dev-only fake OIDC provider image for the auth plugin's `oauth`
# sandbox. Self-contained: this directory is the whole build context.
#
# In a project, codegen wires it into compose.w17.yaml with a `build:` rooted
# at the vendored copy of this directory, so `w17ctl stack build` (or the first
# `stack up` that finds no image) builds it. From a clone of this repository:
#
#   docker build -t ${W17_WORKSPACE:-w17}-w17-fakeidp:dev auth/sandboxes/fakeidp
#
# This image is NEVER shipped to production — a sandbox is throwaway dev
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
