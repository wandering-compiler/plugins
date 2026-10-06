# Contributing

## Layout

```
<plugin>/
├── plugin.yaml          the manifest: name, version, features, the w17 range it supports
├── README.md
├── proto/               the plugin's declarations (types/, queries/, mutations/, business/, …)
└── src/                 the Go module: handlers, libraries, tests
    └── gen/pb/          generated from proto/ — committed, never edited by hand
tools/                   gen-pb, release, the names check, the pinned w17ctl version
```

## The checks

Every pull request runs them, and `main` merges only when the `ci-ok` check is
green. Run them locally with Go and docker:

| | what it checks |
|---|---|
| `make fmt` | gofmt over the hand-written Go |
| `make vet` / `make test` | `go vet`, and the tests with coverage |
| `make check-gen-pb` | the committed `src/gen/pb` is exactly what `proto/` generates; regenerate with `make gen-pb` |
| `make check-render` | the installable form renders with the pinned w17ctl: inert Go, tests carried, no pb |
| `make check-refs` | nothing cites the w17 platform's private docs — state the reason in place |
| `make check-names` | no file, and no file path, names a real project (see below) |
| `make check-tools` | the names checker and any plugin sandbox module build and pass |

`make check` runs them all, and `PLUGIN=<name>` narrows any of them to one plugin.

**Generated pb** comes from plain buf (`tools/gen-pb.sh`). Imports resolve against
the w17 proto vocabulary of the SDK version the plugin's own `src/go.mod`
requires, so the pb and the Go it compiles against come from one SDK. A
directory with its own `buf.gen.yaml` (e.g. `cluster/src/workerpb`) is
regenerated with it and checked the same way.

**The render** is `w17ctl plugin render`, at the version pinned in
`tools/w17ctl-version`. That is the same code a commit install runs, so a
release and a commit install land the same tree.

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

A pull request from a fork does not receive that secret, so its `ci-ok` stays
red. A maintainer brings the branch into this repository to get it checked.
