# Releasing a plugin

## Changelog fragments

A pull request that changes a plugin says what changed for the plugin's users
in a **fragment**: `<plugin>/changes/<name>.md`, starting with a `### ` heading,
a few lines under it. Pull requests never edit `CHANGELOG.md` itself, so they
never conflict over it. CI (`tools/check-changelog.sh`) refuses a pull request
that changes a plugin without a fragment, unless it carries the `no-changelog`
label (tests, comments: nothing a user of the plugin can notice). A fragment
sits directly in `changes/` and ends in `.md`; anything else is never collected.
A release pull request (branch `release/<plugin>-v0.1.0-rc.N`) is exempt only
in the shape `tools/release-pr.sh` gives it: the manifest says that version, and
it changes `plugin.yaml` and `CHANGELOG.md` and deletes fragments, nothing else.

## Cutting a release

1. **Open the release pull request** from an up-to-date, clean `main`:

   ```sh
   git switch main && git pull
   make release-pr PLUGIN=auth
   ```

   `tools/release-pr.sh` picks the version: the manifest's when no tag carries
   it yet, otherwise the next rc after the newest tag. Every plugin is on one
   version line, `v0.1.0-rc.N`: only the rc counter moves; a break is a new rc,
   not a new minor. The pull request sets the version in `plugin.yaml`,
   collects the fragments into `CHANGELOG.md` under `## <version>` (an
   `## Unreleased` section becomes it), and deletes the fragments. Merging it
   is the release decision. `DRY_RUN=1` prepares the commit on the local
   branch and pushes nothing; delete the branch afterwards.
2. **Cut the release** from `main` with that merge:

   ```sh
   git switch main && git pull
   W17_CONSOLE_ADDR=<console> make release RELEASE=auth@v0.1.0-rc.17
   ```

`tools/release.sh` refuses unless:
- the version is `v0.1.0-rc.N`;
- the manifest says that version;
- `CHANGELOG.md` starts with that version's section and `<plugin>/changes/`
  holds no fragment (one merged after the release pull request would ship
  unlisted: open the release pull request again);
- `HEAD` is `origin/main`;
- the tag does not exist yet.

It then does four things:
1. Runs `make check` for the plugin. `SKIP_CHECK=1` replaces this run with a
   check that CI's `ci-ok` passed on that exact commit.
2. Renders the plugin as committed (`git archive`, so nothing untracked can reach
   a release) with the PINNED `w17ctl plugin render` (`tools/w17ctl-version`),
   onto the `releases` branch.
3. Signs it through `w17ctl plugin sign` — the `w17ctl` on your PATH (or
   `W17CTL`), logged in to the console that holds the key. An unsigned release is
   never tagged. Every rendered file is committed (`git add -f`, then checked),
   so the commit is exactly the signed tree whatever your gitignore says.
4. Commits, tags `<plugin>/<version>`, and pushes the `releases` branch and the
   tag **atomically**: both land, or neither does. It never pushes `main`. A
   tag that failed to push is deleted locally, so a retry starts clean. Whether
   a tag is published is decided by the remote, not by a local leftover.

`DRY_RUN=1` renders and commits locally, without signing (that asks the console)
or pushing, and keeps the commit in a worktree for inspection.

A published tag is never moved, and the repository enforces it: a ruleset
forbids updating or deleting `*/v*` tags, for everyone. A second ruleset lets
only repository admins create them. A fix ships as the next version.
