# Releasing a plugin

A release is cut by hand from `main` as merged:

1. **Bump the version** in `<plugin>/plugin.yaml`, in a pull request, and merge it.
   Versions are `v0.MINOR.PATCH-rc.N` until a stable line exists.
2. **Cut the release** from an up-to-date, clean `main`:

   ```sh
   git switch main && git pull
   W17_CONSOLE_ADDR=<console> make release RELEASE=auth@v0.1.0-rc.17
   ```

`tools/release.sh` refuses unless:
- the manifest says that version;
- `HEAD` is `origin/main`;
- the tag does not exist yet.

It then does four things:
1. Runs `make check` for the plugin. `SKIP_CHECK=1` replaces this run with a
   check that CI's `ci-ok` passed on that exact commit.
2. Renders the plugin as committed (`git archive`, so nothing untracked can reach
   a release) with `w17ctl plugin render`, onto the `releases` branch.
3. Signs it through `w17ctl plugin sign`. The console holds the key, and an
   unsigned release is never tagged.
4. Commits, tags `<plugin>/<version>`, and pushes the `releases` branch and the
   tag **atomically**: both land, or neither does. It never pushes `main`. A
   tag that failed to push is deleted locally, so a retry starts clean. Whether
   a tag is published is decided by the remote, not by a local leftover.

`DRY_RUN=1` renders and commits locally, without signing (that asks the console) or pushing.

A published tag is never moved. A fix ships as the next version.
