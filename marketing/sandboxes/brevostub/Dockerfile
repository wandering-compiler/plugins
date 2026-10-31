# Dev-only Brevo API stand-in for the marketing plugin's `brevo`
# sandbox. Self-contained: this directory is the whole build context.
#
# In a project, codegen wires it into compose.w17.yaml with a `build:` rooted
# at the vendored copy of this directory, so `w17ctl stack build` (or the first
# `stack up` that finds no image) builds it. From a clone of this repository:
#
#   docker build -t ${W17_WORKSPACE:-w17}-w17-brevostub:dev marketing/sandboxes/brevostub
#
# This image is NEVER shipped to production — a sandbox is throwaway dev
# infra, started only by a project's dev compose.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /brevostub .

FROM alpine:3.23
RUN adduser -D -u 10001 brevostub
USER brevostub
COPY --from=build /brevostub /usr/local/bin/brevostub
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/brevostub"]
