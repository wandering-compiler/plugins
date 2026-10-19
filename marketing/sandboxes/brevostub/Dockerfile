# Dev-only Brevo API stand-in for the marketing plugin's `brevo`
# sandbox. Build locally:
#
#   docker build -t ${W17_WORKSPACE:-w17}-w17-brevostub:dev marketing/sandboxes/brevostub   (from a clone of this repository)
#
# The marketing plugin's plugin.yaml references the `${W17_WORKSPACE:-w17}-w17-brevostub:dev` tag;
# codegen wires it into the consuming project's compose.w17.yaml. This
# image is NEVER shipped to production — a sandbox is throwaway dev
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
