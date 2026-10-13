# Releasing a plugin

## Changelog fragments

A pull request that changes a plugin says what changed for the plugin's users
in a **fragment**: `<plugin>/changes/<name>.md`, starting with a `### ` heading,
a few lines under it. Pull requests never edit `CHANGELOG.md` itself, so they
never conflict over it. CI (`tools/check-changelog.sh`) refuses a pull request
that changes a plugin without a fragment, unless it carries the `no-changelog`
label (tests, comments: nothing a user of the plugin can notice). A fragment
sits directly in `changes/`, ends in `.md` and does not start with a dot;
anything else is never collected.
A release pull request (branch `release/<plugin>-v0.1.0-rc.N`) is exempt only
in the shape `tools/release-pr.sh` gives it: the manifest says that version, and
it changes the version in `plugin.yaml`, `CHANGELOG.md`, and deletes fragments,
nothing else.

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
2. **The release workflow cuts it** (`.github/workflows/release.yml`). When CI
   passes on the merge commit, it runs `tools/release.sh` for every plugin
   whose `CHANGELOG.md` that commit changed, whose changelog now opens with
   the manifest's version and whose `changes/` holds no fragment (what a
   release pull request leaves): it signs the plugin and tags the commit.
   An ordinary pull request that edits a manifest is not a release, even
   while the manifest names a version that is not tagged yet. Nothing else is
   needed. A version whose tag already exists is
   skipped, and every plugin is tried before the run fails, so a re-run
   releases only what is still missing. To retry a failed run, or release from
   `main` by hand, run the workflow with the plugin's name ("Run workflow" on
   the Actions page), or locally:

   ```sh
   git switch main && git pull
   W17_CONSOLE_ADDR=<console> make release RELEASE=auth@v0.1.0-rc.17
   ```

A release is a commit of `main`. The tag `<plugin>/v<version>` sits on that
commit, and a consumer's `w17ctl` fetches it and renders the plugin itself.
There is no second branch: the `releases` branch held the rendered form of the
releases cut before this, and its tags stay installable.

`tools/release.sh` refuses unless:
- the version is `v0.1.0-rc.N`;
- the manifest says that version;
- `CHANGELOG.md` starts with that version's section and `<plugin>/changes/`
  holds no fragment (one merged after the release pull request would ship
  unlisted: open the release pull request again);
- `HEAD` is a commit of `origin/main` (the workflow tags the commit CI passed
  on, even when `main` has moved on since);
- the tag does not exist yet;
- `<plugin>/plugin.sig` is not committed (the signature travels in the tag, and
  `w17ctl` refuses a tag whose tree carries a second one).

It then does three things:
1. Runs `make check` for the plugin. `SKIP_CHECK=1` replaces this run with a
   check that CI's `ci-ok` passed on that exact commit; the workflow uses it.
2. Signs the plugin as committed (`git archive`, so nothing untracked can reach
   it) through `w17ctl plugin sign`, which digests the tree, asks the console to
   sign the digest and confirms the console verifies the result. The key never
   leaves the console. An unsigned release is never tagged. By hand this is the
   `w17ctl` on your PATH (or `W17CTL`); the workflow signs with the pinned one.
3. Tags the commit with an annotated tag whose message carries the signature
   between `-----BEGIN W17 PLUGIN SIGNATURE-----` and
   `-----END W17 PLUGIN SIGNATURE-----`, and pushes the tag. A tag that failed to
   push is deleted locally, so a retry starts clean. Whether a tag is published
   is decided by the remote, not by a local leftover.

`DRY_RUN=1` signs nothing and pushes nothing; it prints the tag message it would
write.

**Why the author tree is signed.** The render depends on the version of
`w17ctl` that runs it, and a consumer renders with their own. The committed tree
is the same for everyone, so every client computes the digest that was signed.
`w17ctl` v0.1.0-rc.74 and newer read the signature from the tag and verify it;
an older one installs such a release as unsigned (it does not refuse it).

**The workflow's secrets** live in the `release` environment, which only `main`
may use, so a workflow edited on another branch never sees them:
- `W17_SIGN_TOKEN`: a console token whose account may sign plugin releases;
- `RELEASE_TAG_TOKEN`: a token allowed to create `*/v*` tags.

A published tag is never moved, and the repository enforces it: a ruleset
forbids updating or deleting `*/v*` tags, for everyone. A second ruleset lets
only repository admins create them. A fix ships as the next version.
