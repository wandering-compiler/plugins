# auth plugin (v3 POC)

Authored Go business handlers + DQL primitives + proto schema for
email/password authentication and bearer tokens.

This is the **G3-POC** snapshot — manual rewrite of the v2 auth
plugin to the v3 layout (the plugin source lives here, at
`plugins/auth/`). Coexistence is intentional: w17 storage codegen
still uses the v2 location + emits the F3/G2-F templates today;
G3-D deletes those once the v3 staging pipeline (G3-B/C) lands.

Layout follows
[`docs/specs/plugins/business-handlers.md`](../../docs/specs/plugins/business-handlers.md):

```
plugins/auth/
├── go.mod              ← module github.com/wandering-compiler/platform/plugins/auth
├── plugin.yaml         ← manifest (go_module field is v3-new)
├── proto/              ← schema source (same content as v2)
│   ├── types/
│   ├── queries/
│   ├── mutations/
│   ├── services/
│   └── events/
├── pb/                 ← Go pb (POC: hand-written stubs; G3-F regenerates from proto)
└── handlers/           ← authored Go business handlers
    └── auth_service.go ← Authenticate + SignIn (formerly F3/G2-F template emit)
```

## POC scope

- Layout proves compileable in isolation (`go build ./...` green)
- Handler source matches the spec's reference shape
  (`*Handler` struct, SDK-injected deps, opaque
  Unauthenticated failure mode, anti-enumeration)
- pb/ contains hand-written stubs covering only the surface
  the POC handler imports — G3-F (`w17ctl plugin build`) will
  regenerate from proto with full coverage

## Out of scope for POC

- Real protoc-driven pb generation (G3-F)
- Staging + per-activation import rewriting (G3-B)
- Handler discovery + RegisterPlugin codegen (G3-C)
- Deleting v2 templates + old proto location (G3-D)
- SDK auditor (G3-G)

The v2 auth plugin keeps functioning unchanged until G3-D.

## Regenerating the committed `src/gen/pb`

The `src/gen/pb/*.pb.go` stubs exist only for this plugin's local
dev/test loop (`go test ./src/...`); the project codegen generates
its own per-activation pb at staging time and never uses them.
Regenerate them after editing any `proto/` file with:

```
w17ctl plugin gen-pb plugins/auth
```

It reads `go_module` from `plugin.yaml` and drives the same `bufrun`
pipeline as the project codegen — output is byte-stable across runs.
It needs a reachable CONSOLE: the vocabulary is resolved server-side,
the way every other compile is. (It used to say "from the w17ctl
binary's embedded copy"; that embed is gone —
docs/decisions/client-carries-compiler-payloads.md §2.)
(This replaces the old hand-rolled `regen-pb.sh`.)
