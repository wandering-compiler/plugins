# w17 plugins

The source of the plugins the [w17](https://github.com/wandering-compiler) compiler
installs into a project: `auth`, `agent`, `cluster`, `grant`, `marketing` and `payment`.

A plugin is a directory with a `plugin.yaml` manifest, its `proto/` declarations
and its Go handlers under `src/`. A project never imports a plugin as a Go module.
`w17ctl plugin install` places a release into the project, and the project's own
codegen stages the sources into its service bundles.

## One branch, tagged releases

`main` holds the **author tree**: live Go, a real `go.mod`, the tests, the
generated pb. It changes through pull requests only. A release is a tag on a
commit of `main`, `<plugin>/v<version>`, signed (RELEASING.md). `w17ctl` renders
the plugin into its installable form when it installs it. Releases cut before
this live on the `releases` branch, rendered, and stay installable. A release
tagged on `main` carries its signature in the tag, which w17ctl v0.1.0-rc.74 and
newer verify; an older w17ctl installs it as unsigned.

A consumer installs a tag:

```sh
w17ctl plugin install https://github.com/wandering-compiler/plugins#auth/v0.1.0-rc.19
```

To try an unreleased change, install a commit of `main` (`…#auth@<sha>`). It
lands unsigned. w17ctl v0.1.0-rc.66 and newer render the author tree on install,
so it places what a release of that commit would. v0.1.0-rc.65 and older place
the raw author tree, with its generated pb, sandboxes and a live go.mod (tests
are dropped), so upgrade w17ctl before installing a commit.

## Working on a plugin

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make check PLUGIN=<name>` runs
every check CI runs. Every pull request is tested, and `main` merges only green.

A merged release pull request is released by CI: [RELEASING.md](RELEASING.md).
