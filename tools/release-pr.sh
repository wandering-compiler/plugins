#!/usr/bin/env bash
# release-pr.sh — open the pull request that releases ONE plugin.
#
#   usage: tools/release-pr.sh <plugin>
#
# The version released is the manifest's when no tag carries it yet (a bump
# that already landed), otherwise the next rc after the newest tag. The pull
# request:
#   - sets that version in <plugin>/plugin.yaml;
#   - collects <plugin>/changes/*.md into <plugin>/CHANGELOG.md under
#     `## <version>` (an `## Unreleased` section at the top becomes that
#     section; an existing section for the version gets the fragments added);
#   - deletes the fragments.
#
# Merging it is the release decision. Nothing here tags, signs or pushes main:
# the branch goes up, and the pull request goes through CI like any other.
#   env: DRY_RUN=1  prepare the commit on a local branch, push nothing
set -euo pipefail

PLUGIN="${1:?usage: $0 <plugin>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f "$PLUGIN/plugin.yaml" ] || { echo "!! no plugin $PLUGIN here" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "!! the working tree is not clean" >&2; exit 1; }
git fetch --quiet origin main --tags
if [ "${DRY_RUN:-0}" != 1 ] && [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
	echo "!! HEAD is not origin/main — check out main as merged and pull first" >&2; exit 1
fi

manifest="$(sed -n 's/^version:[[:space:]]*//p' "$PLUGIN/plugin.yaml" | head -1 | tr -d "\"' ")"
rc() { echo "${1##*.}"; }
last="$(git tag -l "$PLUGIN/v0.1.0-rc.*" | sed "s|^$PLUGIN/v||" | sort -V | tail -1)"
if [ -z "$last" ] || [ "$(rc "$manifest")" -gt "$(rc "$last")" ]; then
	version="$manifest" # a bump that landed already, not yet tagged
elif [ "$manifest" = "$last" ]; then
	version="0.1.0-rc.$(( $(rc "$last") + 1 ))"
else
	echo "!! $PLUGIN/plugin.yaml says $manifest, behind the newest tag $last" >&2; exit 1
fi
echo "$version" | grep -Eq '^0\.1\.0-rc\.[0-9]+$' || { echo "!! $version is not on the version line 0.1.0-rc.N" >&2; exit 1; }

shopt -s nullglob
fragments=("$PLUGIN"/changes/*.md)
top="$(grep -m1 '^## ' "$PLUGIN/CHANGELOG.md" || true)"
if [ ${#fragments[@]} -eq 0 ] && [ "$top" != "## Unreleased" ] && [ "$top" != "## $version" ]; then
	echo "!! $PLUGIN has no change fragments and no unreleased changelog section — nothing to release" >&2
	exit 1
fi

branch="release/$PLUGIN-v$version"
git switch --quiet -c "$branch"

sed -i "s/^version:.*/version: $version/" "$PLUGIN/plugin.yaml"

# The fragments, newest name last, each separated by a blank line.
body=""
for f in "${fragments[@]}"; do
	body+="$(cat "$f")"$'\n\n'
done
python3 - "$PLUGIN/CHANGELOG.md" "$version" "$body" <<'PY'
import sys
path, version, body = sys.argv[1], sys.argv[2], sys.argv[3].rstrip("\n")
lines = open(path).read().split("\n")
head = "## " + version
idx = next((i for i, l in enumerate(lines) if l.startswith("## ")), None)
if idx is not None and lines[idx] in ("## Unreleased", head):
    lines[idx] = head
    if body:
        # Fragments go first in the section: they are the newest changes.
        lines[idx + 1:idx + 1] = [""] + body.split("\n")
else:
    at = idx if idx is not None else len(lines)
    lines[at:at] = [head, ""] + body.split("\n") + [""]
open(path, "w").write("\n".join(lines))
PY
[ ${#fragments[@]} -eq 0 ] || git rm --quiet "${fragments[@]}"
git add "$PLUGIN/plugin.yaml" "$PLUGIN/CHANGELOG.md"
# Empty when the bump and the changelog landed already: merging is still the
# release decision, so the pull request exists anyway.
git commit --quiet --allow-empty -m "release: $PLUGIN v$version"
echo ">> $branch: $PLUGIN v$version, ${#fragments[@]} fragment(s)"

[ "${DRY_RUN:-0}" = 1 ] && { echo ">> DRY_RUN: not pushed; inspect with git show"; exit 0; }
git push --quiet -u origin "$branch"
gh pr create --base main --head "$branch" --title "release: $PLUGIN v$version" \
	--body "Releases $PLUGIN v$version: the version in plugin.yaml, and the changelog collected from $PLUGIN/changes/. Merging this is the release decision."
