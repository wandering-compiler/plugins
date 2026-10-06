#!/usr/bin/env bash
# release.sh — cut ONE plugin release: render, sign, commit to `releases`, tag.
#
#   usage: tools/release.sh <plugin>@<version>      e.g. auth@v0.1.0-rc.17
#   env:   W17CTL            the w17ctl that signs (default: w17ctl on PATH)
#          W17_CONSOLE_ADDR  the console holding the signing key (w17ctl's env)
#          DRY_RUN=1         do everything except push
#          SKIP_CHECK=1      skip `make check` when CI's `ci-ok` passed on this
#                            exact commit of main (verified through gh)
#
# Two lines of history live here, on purpose:
#
#   main      the AUTHOR tree — what people work on, through pull requests.
#   releases  the INSTALLABLE form — one commit per release, each tagged
#             `<plugin>/v<version>`. A consumer's w17ctl fetches the tag.
#
# The installable form is what tools/render.sh produces: inert Go (`.src`),
# tests included, generated pb left out. A release is cut FROM main and never
# commits to it; the release commit lands on `releases` only.
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

case "$VERSION" in v*) ;; *) echo "!! the version starts with v: $VERSION" >&2; exit 1 ;; esac
[ -f "$PLUGIN/plugin.yaml" ] || { echo "!! no plugin $PLUGIN here" >&2; exit 1; }
MANIFEST="v$(sed -n 's/^version:[[:space:]]*//p' "$PLUGIN/plugin.yaml" | head -1 | tr -d '"'"'"' ')"
[ "$MANIFEST" = "$VERSION" ] || {
	echo "!! $PLUGIN/plugin.yaml says $MANIFEST, the release would be $VERSION." >&2
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
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
	echo "!! $TAG already exists — a published tag is never moved." >&2
	exit 1
fi
command -v "$W17CTL" >/dev/null || { echo "!! no w17ctl ($W17CTL) — signing goes through it" >&2; exit 1; }

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
trap 'git worktree remove --force "$WORK/releases" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
git worktree add --quiet "$WORK/releases" origin/releases
tools/render.sh "$PLUGIN" "$WORK/rendered"
rm -rf "$WORK/releases/$PLUGIN"
cp -R "$WORK/rendered/$PLUGIN" "$WORK/releases/$PLUGIN"

echo ">> signing $PLUGIN ..."
( cd "$WORK/releases" && "$W17CTL" plugin sign "$PLUGIN" ) || {
	echo "!! signing failed — not tagging an unsigned release. Check W17_CONSOLE_ADDR and" >&2
	echo "   that you are signed in with a role that may sign." >&2
	exit 1
}

MAIN_SHA="$(git rev-parse HEAD)"
(
	cd "$WORK/releases"
	git add -A "$PLUGIN"
	git commit --quiet -m "$PLUGIN $VERSION" -m "Rendered from main $MAIN_SHA."
	git tag -a "$TAG" -m "$PLUGIN $VERSION"
)
if [ "${DRY_RUN:-0}" = 1 ]; then
	echo ">> DRY RUN — would push releases → $(git -C "$WORK/releases" rev-parse --short HEAD) and tag $TAG"
	git tag -d "$TAG" >/dev/null
	exit 0
fi
# A plain push, never --force: a rejected push means someone else released in
# the meantime, and that must fail loudly rather than be overwritten.
git -C "$WORK/releases" push --quiet origin "HEAD:releases" "refs/tags/$TAG"
echo ">> released $TAG → $(git -C "$WORK/releases" rev-parse --short HEAD) (from main $(git rev-parse --short "$MAIN_SHA"))"
