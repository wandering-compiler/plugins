#!/usr/bin/env bash
# release.sh — cut ONE plugin release: render, sign, commit to `releases`, tag.
#
#   usage: tools/release.sh <plugin>@<version>      e.g. auth@v0.1.0-rc.17
#   env:   W17CTL            the w17ctl that SIGNS (default: w17ctl) — logged in to
#                            the console that holds the key. The RENDER always uses
#                            the pinned version (tools/w17ctl.sh), never this one.
#          W17_CONSOLE_ADDR  the console holding the signing key (w17ctl's env)
#          DRY_RUN=1         render and commit locally, no signature, no push; the
#                            commit is kept in a worktree for inspection
#          SKIP_CHECK=1      skip `make check` when CI's `ci-ok` passed on this
#                            exact commit of main (verified through gh)
#
# Two lines of history live here, on purpose:
#
#   main      the AUTHOR tree — what people work on, through pull requests.
#   releases  the INSTALLABLE form — one commit per release, each tagged
#             `<plugin>/v<version>`. A consumer's w17ctl fetches the tag.
#
# The installable form is `w17ctl plugin render`'s output, at the version pinned
# in tools/w17ctl-version, over the plugin AS COMMITTED (git archive), so nothing
# in the working directory that git does not track can reach a release.
# A release is cut FROM main and never commits to it.
#
# The signature is over the rendered tree, because that is what a consumer
# fetches. The key never passes through here: `w17ctl plugin sign` digests the
# tree locally and asks the console to sign the digest.
set -euo pipefail

SPEC="${1:?usage: $0 <plugin>@<version>   (e.g. auth@v0.1.0-rc.17)}"
PLUGIN="${SPEC%@*}"
VERSION="${SPEC#*@}"
TAG="$PLUGIN/$VERSION"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W17CTL="${W17CTL:-w17ctl}"
cd "$ROOT"

field() { sed -n "s/^$1:[[:space:]]*//p" "$PLUGIN/plugin.yaml" | head -1 | tr -d '"'"'"' '; }
case "$VERSION" in v*) ;; *) echo "!! the version starts with v: $VERSION" >&2; exit 1 ;; esac
[ -f "$PLUGIN/plugin.yaml" ] || { echo "!! no plugin $PLUGIN here" >&2; exit 1; }
[ "$(field name)" = "$PLUGIN" ] || {
	echo "!! $PLUGIN/plugin.yaml declares name: $(field name) — the directory and the manifest disagree" >&2
	exit 1
}
[ "v$(field version)" = "$VERSION" ] || {
	echo "!! $PLUGIN/plugin.yaml says v$(field version), the release would be $VERSION." >&2
	echo "   Bump the manifest in a pull request first — a tag that disagrees with the" >&2
	echo "   manifest it ships is two answers to one question." >&2
	exit 1
}

# Released from main as merged, never from a local edit.
git fetch --quiet origin main releases --tags
[ -z "$(git status --porcelain)" ] || { echo "!! the working tree is not clean" >&2; exit 1; }
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || {
	echo "!! HEAD is not origin/main — check out main as merged and pull first" >&2
	exit 1
}
# The REMOTE decides whether a tag exists; a local leftover from a failed run
# is not a release.
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
	echo "!! $TAG is already published — a published tag is never moved." >&2
	exit 1
fi
git tag -d "$TAG" >/dev/null 2>&1 || true
RENDER="$(tools/w17ctl.sh)"
if [ "${DRY_RUN:-0}" != 1 ]; then
	command -v "$W17CTL" >/dev/null || { echo "!! no w17ctl ($W17CTL) to sign with" >&2; exit 1; }
fi

if [ "${SKIP_CHECK:-0}" = 1 ]; then
	# Allowed only when CI already passed on this exact commit of main.
	state="$(gh api "repos/{owner}/{repo}/commits/$(git rev-parse HEAD)/check-runs" \
		-q '[.check_runs[] | select(.name == "ci-ok")][0].conclusion' 2>/dev/null || true)"
	[ "$state" = "success" ] || {
		echo "!! SKIP_CHECK=1 needs a green \`ci-ok\` on $(git rev-parse --short HEAD) (got: ${state:-none})" >&2
		exit 1
	}
	echo ">> CI passed on main $(git rev-parse --short HEAD) — not re-running the checks"
else
	echo ">> checking $PLUGIN on main ($(git rev-parse --short HEAD)) ..."
	make --no-print-directory check PLUGIN="$PLUGIN"
fi

WORK="$(mktemp -d -t w17-plugin-release.XXXXXX)"
PUSHED=0
KEEP=0
cleanup() {
	# A tag that did not reach the remote is not a release; leaving it would
	# only confuse the next run.
	[ "$PUSHED" = 1 ] || git tag -d "$TAG" >/dev/null 2>&1 || true
	[ "$KEEP" = 1 ] && return
	git worktree remove --force "$WORK/releases" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/committed"
git archive HEAD "$PLUGIN" | tar -x -C "$WORK/committed"
git worktree add --quiet "$WORK/releases" origin/releases
"$RENDER" plugin render "$WORK/committed/$PLUGIN" --out "$WORK/rendered/$PLUGIN" >/dev/null
rm -rf "${WORK:?}/releases/$PLUGIN"
cp -R "$WORK/rendered/$PLUGIN" "$WORK/releases/$PLUGIN"

if [ "${DRY_RUN:-0}" = 1 ]; then
	echo ">> DRY RUN — not signing (that asks the console)"
else
	echo ">> signing $PLUGIN ..."
	( cd "$WORK/releases" && "$W17CTL" plugin sign "$PLUGIN" ) || {
		echo "!! signing failed — not tagging an unsigned release. Check W17_CONSOLE_ADDR and" >&2
		echo "   that you are signed in with a role that may sign." >&2
		exit 1
	}
fi

MAIN_SHA="$(git rev-parse HEAD)"
# Who releases is whoever runs this; a box with no git identity falls back to
# the author of the main commit being released.
NAME="$(git config user.name || git log -1 --format=%an)"
EMAIL="$(git config user.email || git log -1 --format=%ae)"
(
	cd "$WORK/releases"
	# -f: what was signed is the whole rendered directory, so every file in it
	# is committed, whatever the releaser's own gitignore rules say. A file left
	# out would make the signature INVALID for every consumer of an immutable tag.
	git add -A -f "$PLUGIN"
	# Only what is still untracked (??) or ignored (!!) after the add; staged
	# entries (A, M, D) are the release itself.
	left="$(git status --porcelain --ignored -- "$PLUGIN" | grep -E '^(\?\?|!!) ' || true)"
	[ -z "$left" ] || { echo "!! files under $PLUGIN would not be committed:" >&2; echo "$left" >&2; exit 1; }
	git -c user.name="$NAME" -c user.email="$EMAIL" commit --quiet \
		-m "$PLUGIN $VERSION" -m "Rendered from main $MAIN_SHA."
	git -c user.name="$NAME" -c user.email="$EMAIL" tag -a "$TAG" -m "$PLUGIN $VERSION"
)
if [ "${DRY_RUN:-0}" = 1 ]; then
	KEEP=1
	echo ">> DRY RUN — would push releases → $(git -C "$WORK/releases" rev-parse --short HEAD) and tag $TAG"
	echo "   the release commit is kept for inspection in $WORK/releases"
	echo "   (remove it with: git worktree remove --force $WORK/releases && rm -rf $WORK)"
	exit 0
fi
# ATOMIC: the branch and the tag land together or not at all — a tag pointing at
# a commit that never reached `releases` is a release nobody can trace. A plain
# push, never --force: a rejection means someone else released in the meantime.
git -C "$WORK/releases" push --quiet --atomic origin "HEAD:refs/heads/releases" "refs/tags/$TAG"
PUSHED=1
echo ">> released $TAG → $(git -C "$WORK/releases" rev-parse --short HEAD) (from main $(git rev-parse --short "$MAIN_SHA"))"
