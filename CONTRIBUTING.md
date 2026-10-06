# Contributing

## Layout

```
<plugin>/
├── plugin.yaml          the manifest: name, version, features, the w17 range it supports
├── README.md
├── proto/               the plugin's declarations (types/, queries/, mutations/, business/, …)
└── src/                 the Go module: handlers, libraries, tests
    └── gen/pb/          generated from proto/ — committed, never edited by hand
tools/                   gen-pb, render, release, the names check
```

## The checks

Every pull request runs them, and `main` merges only when the `ci-ok` check is
green. Run them locally with Go and docker:

| | what it checks |
|---|---|
| `make fmt` | gofmt over the hand-written Go |
| `make vet` / `make test` | `go vet`, and the tests with coverage |
| `make check-gen-pb` | the committed `src/gen/pb` is exactly what `proto/` generates; regenerate with `make gen-pb` |
| `make check-render` | the installable form renders: inert Go, tests carried, no pb |
| `make check-names` | no file names a real project (see below) |

`make check` runs them all, and `PLUGIN=<name>` narrows any of them to one plugin.

**Generated pb** comes from plain buf (`tools/gen-pb.sh`). Imports resolve against
the w17 proto vocabulary of the SDK version pinned in
`tools/vocabulary-sdk-version`. Bump it in a pull request when a plugin starts
using something newer.

## Tests

A plugin is the part of w17 other people's projects run, so its tests are the
contract. Cover the edge cases, not only the happy path: refusals, expiry,
concurrency, malformed input. The coverage summary of every run is on the
pull request's checks page.

## Keep it anonymous

This repository is public. Fixtures, examples, comments and test data use
obviously invented names (`acme`, `example.com`, `tenant-a`), never a real
company, customer or project, not even one that uses w17. `make check-names`
enforces it against a list held as a CI secret. A finding prints the file and
line, never the name.
