#!/usr/bin/env bash
# release.sh — cut ONE plugin release: sign the plugin as committed on main and
# tag that commit, with the signature in the tag's message.
#
#   usage: tools/release.sh <plugin>@<version>      e.g. auth@v0.1.0-rc.17
#   env:   W17CTL            the w17ctl that SIGNS (default: w17ctl) — signed in
#                            to the console that holds the key, or given a token
#                            in W17_TOKEN (the release workflow does that)
#          W17_CONSOLE_ADDR  the console holding the signing key (w17ctl's env)
#          DRY_RUN=1         sign nothing, push nothing; print the tag message
#          SKIP_CHECK=1      skip `make check` when CI's `ci-ok` passed on this
#                            exact commit (verified through gh)
#
# A release is a commit of main: the tag `<plugin>/v<version>` sits on it, and a
# consumer's w17ctl fetches that tag and renders the plugin itself. Nothing is
# committed anywhere, so main stays the one line of history.
#
# The signature is over the plugin's AUTHOR tree as committed (git archive, so
# nothing untracked can reach it): the render depends on the consumer's w17ctl,
# the committed tree does not. The key never passes through here: `w17ctl plugin
# sign` digests the tree locally and asks the console to sign the digest. The
# signature travels in the annotated tag's message, between the BEGIN/END lines
# w17ctl reads (docs/decisions in the platform: a release tag carries the
# signature of the author tree).
#
# The `releases` branch held the rendered form of every earlier release. Its
# tags stay installable; nothing is added to it any more.
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
# One version line for every plugin and the platform: v0.1.0-rc.N (Makefile's
# check-versions says why).
echo "$VERSION" | grep -Eq '^v0\.1\.0-rc\.[0-9]+$' || {
	echo "!! $VERSION is not on the version line — every release is v0.1.0-rc.N" >&2; exit 1; }
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

# Released from main as merged, never from a local edit. HEAD may be behind
# origin/main (the release workflow tags the commit CI passed on, and main can
# move on meanwhile), but it has to be ON main.
git fetch --quiet origin main --tags
[ -z "$(git status --porcelain)" ] || { echo "!! the working tree is not clean" >&2; exit 1; }
git merge-base --is-ancestor HEAD origin/main || {
	echo "!! HEAD is not on origin/main — check out main as merged and pull first" >&2
	exit 1
}
# What ships is what the changelog says: the release pull request
# (tools/release-pr.sh) collected every fragment under this version. A fragment
# merged after it would ship unlisted, and be listed under the next version.
# -z: a name git would quote (non-ASCII, a double quote) still ends in .md.
fragments="$(git ls-tree -z --name-only HEAD "$PLUGIN/changes/" | tr '\0' '\n' | grep '\.md$' || true)"
[ -z "$fragments" ] || {
	echo "!! $PLUGIN/changes/ holds fragments the changelog does not list yet:" >&2
	echo "$fragments" >&2
	echo "   open the release pull request again (make release-pr PLUGIN=$PLUGIN), merge it, then release" >&2
	exit 1
}
[ "$(grep -m1 '^## ' "$PLUGIN/CHANGELOG.md" 2>/dev/null)" = "## ${VERSION#v}" ] || {
	echo "!! $PLUGIN/CHANGELOG.md does not start with a ## ${VERSION#v} section — release through make release-pr" >&2
	exit 1
}
# The REMOTE decides whether a tag exists; a local leftover from a failed run
# is not a release.
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
	echo "!! $TAG is already published — a published tag is never moved." >&2
	exit 1
fi
git tag -d "$TAG" >/dev/null 2>&1 || true
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
cleanup() {
	# A tag that did not reach the remote is not a release; leaving it would
	# only confuse the next run.
	[ "$PUSHED" = 1 ] || git tag -d "$TAG" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

SHA="$(git rev-parse HEAD)"
git archive "$SHA" "$PLUGIN" | tar -x -C "$WORK"

# The tag message: a title, where it came from, and the signature block. The
# block is exactly what `plugin sign --print` writes, which also confirms the
# console verifies it before printing.
{
	printf '%s %s\n\nFrom main %s.\n\n' "$PLUGIN" "$VERSION" "$SHA"
	echo "-----BEGIN W17 PLUGIN SIGNATURE-----"
	if [ "${DRY_RUN:-0}" = 1 ]; then
		echo "(DRY RUN: not signed — that asks the console)"
	else
		echo ">> signing $PLUGIN ..." >&2
		sig="$("$W17CTL" plugin sign --print "$WORK/$PLUGIN")" || {
			echo "!! signing failed — not tagging an unsigned release. Check W17_CONSOLE_ADDR and" >&2
			echo "   that you are signed in (or W17_TOKEN is set) with a role that may sign." >&2
			exit 1
		}
		# $(…) drops the trailing newlines; the block's own lines are kept as written.
		[ "$(printf '%s\n' "$sig" | head -1)" = "w17-plugin-sig-file/1" ] || {
			echo "!! plugin sign printed something that is not a signature file:" >&2
			printf '%s\n' "$sig" >&2
			exit 1
		}
		printf '%s\n' "$sig"
	fi
	echo "-----END W17 PLUGIN SIGNATURE-----"
} > "$WORK/message"

if [ "${DRY_RUN:-0}" = 1 ]; then
	echo ">> DRY RUN — would tag $TAG on $(git rev-parse --short "$SHA") with:"
	sed 's/^/   /' "$WORK/message"
	exit 0
fi

# Who releases is whoever runs this; a box with no git identity falls back to
# the author of the commit being released.
NAME="$(git config user.name || git log -1 --format=%an "$SHA")"
EMAIL="$(git config user.email || git log -1 --format=%ae "$SHA")"
# verbatim: git's default cleanup would rewrite the message (comment lines,
# blank runs), and the signature block has to arrive as signed.
git -c user.name="$NAME" -c user.email="$EMAIL" tag -a --cleanup=verbatim -F "$WORK/message" "$TAG" "$SHA"
# A plain push, never --force: a rejection means someone else released this
# version in the meantime, and a published tag is never moved.
git push --quiet origin "refs/tags/$TAG"
PUSHED=1
echo ">> released $TAG → main $(git rev-parse --short "$SHA")"
