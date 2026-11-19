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
commit of `main`, `<plugin>/v<version>`, signed (RELEASING.md); `w17ctl` checks
the signature and renders the plugin into its installable form when it installs
it. Releases cut before tags moved to `main` live on the `releases` branch and
stay installable.

A consumer installs a release:

```sh
w17ctl plugin install https://github.com/wandering-compiler/plugins#auth/v0.1.0
```

To try an unreleased change, install a commit of `main` (`…#auth@<sha>`). It
lands unsigned, rendered the way a release of that commit would be.

## Versions

Plugins follow the w17 version line. Everything on one minor line works
together: a plugin `0.1.x` with an SDK and a w17ctl `0.1.y`. A fix is a patch
release (`0.1.1`); a new feature or an incompatible change goes out as release
candidates of the next minor (`0.2.0-rc.N`). The modules declare the Go line
in `go.version` (`go 1.27.0` today).

## License

MIT, see [LICENSE](LICENSE).

## Working on a plugin

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make check PLUGIN=<name>` runs
every check CI runs. Every pull request is tested, and `main` merges only green.

A merged release pull request is released by CI: [RELEASING.md](RELEASING.md).
