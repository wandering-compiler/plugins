# w17 plugins

The source of the plugins the [w17](https://github.com/wandering-compiler) compiler
installs into a project: `auth`, `agent`, `cluster` and `payment`.

A plugin is a directory with a `plugin.yaml` manifest, its `proto/` declarations
and its Go handlers under `src/`. A project never imports a plugin as a Go module.
`w17ctl plugin install` places a release into the project, and the project's own
codegen stages the sources into its service bundles.

## Two branches

| branch | holds | who writes it |
|---|---|---|
| `main` | the **author tree**: live Go, a real `go.mod`, the tests, the generated pb | pull requests only |
| `releases` | the **installable form**: one commit per release, tagged `<plugin>/v<version>` | `make release` |

A consumer installs a tag:

```sh
w17ctl plugin install https://github.com/wandering-compiler/plugins#auth/v0.1.0-rc.16
```

To try an unreleased change, install a commit of `main` (`…#auth@<sha>`). The
client renders the author tree with the same `w17ctl plugin render` a release
uses, so it lands what a release of that commit would, unsigned. This needs a
w17ctl that renders an author tree on install. An older one places the raw tree,
tests and generated pb included.

## Working on a plugin

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make check PLUGIN=<name>` runs
every check CI runs. Every pull request is tested, and `main` merges only green.

Releases are cut by hand, through [RELEASING.md](RELEASING.md).
