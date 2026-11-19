#!/usr/bin/env bash
# release-pr.sh — open the pull request that releases ONE plugin.
#
#   usage: tools/release-pr.sh <plugin>
#
# The version released is $VERSION when it is given (0.1.0, 0.2.0-rc.1: a
# release, or the first candidate of the next minor); otherwise the
# manifest's when no tag carries it yet (a bump that already landed), the
# next rc after an rc, or the next patch after a release. It must be newer
# than the newest tag. The pull request:
#   - sets that version in <plugin>/plugin.yaml;
#   - collects <plugin>/changes/*.md into <plugin>/CHANGELOG.md under
#     `## <version>` (an `## Unreleased` section at the top becomes that
#     section; an existing section for the version gets the fragments added);
#   - deletes the fragments.
#
# Merging it is the release decision. Nothing here tags, signs or pushes main:
# the branch goes up, and the pull request goes through CI like any other.
#   env: DRY_RUN=1  prepare the commit on a local branch, push nothing; from
#                   any HEAD (for trying it out), so delete the branch after
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

# A version: 0.MINOR.PATCH, a release candidate of one with -rc.N.
VERRE='^0\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
# newest prints the newest of its stdin's versions, a release above its own
# candidates (sort -V alone puts 0.1.0 below 0.1.0-rc.1; ~ sorts first).
newest() { sed 's/-rc\./~rc./' | sort -V | tail -1 | sed 's/~rc\./-rc./'; }
manifest="$(sed -n 's/^version:[[:space:]]*//p' "$PLUGIN/plugin.yaml" | head -1 | tr -d "\"' ")"
echo "$manifest" | grep -Eq "$VERRE" || { echo "!! $PLUGIN/plugin.yaml says $manifest, not a version (0.MINOR.PATCH, or -rc.N of one)" >&2; exit 1; }
# The newest tag on a version's minor line: the line is what one release of the
# platform works with, and a tag on another line (cluster's 0.2.0-rc.N, cut by
# mistake and immutable since) neither blocks nor follows it.
line() { echo "$1" | cut -d. -f1,2; }
newest_on() { git tag -l "$PLUGIN/v$1.*" | sed "s|^$PLUGIN/v||" | grep -E "$VERRE" | newest || true; }
# (cluster's 0.2 line starts at 0.2.0-rc.11 for that reason.)
if [ -n "${VERSION:-}" ]; then
	version="${VERSION#v}"
	last="$(newest_on "$(line "$version")")"
else
	last="$(newest_on "$(line "$manifest")")"
	if [ -z "$last" ] || [ "$(printf '%s\n%s\n' "$manifest" "$last" | newest)" != "$last" ]; then
		version="$manifest" # a bump that landed already, not yet tagged
	elif [[ "$last" == *-rc.* ]]; then
		version="${last%-rc.*}-rc.$(( ${last##*.} + 1 ))"
	else
		IFS=. read -r ma mi pa <<<"$last"
		version="$ma.$mi.$((pa + 1))"
	fi
fi
echo "$version" | grep -Eq "$VERRE" || { echo "!! $version is not a version (0.MINOR.PATCH, or -rc.N of one)" >&2; exit 1; }
if [ -n "$last" ] && { [ "$version" = "$last" ] || [ "$(printf '%s\n%s\n' "$version" "$last" | newest)" != "$version" ]; }; then
	echo "!! $version is not newer than the newest tag $last" >&2; exit 1
fi

shopt -s nullglob
fragments=("$PLUGIN"/changes/*.md)
top="$(grep -m1 '^## ' "$PLUGIN/CHANGELOG.md" 2>/dev/null || true)"
if [ ${#fragments[@]} -eq 0 ] && [ "$top" != "## Unreleased" ] && [ "$top" != "## $version" ]; then
	echo "!! $PLUGIN has no change fragments and no unreleased changelog section — nothing to release" >&2
	exit 1
fi

branch="release/$PLUGIN-v$version"
if git rev-parse --verify --quiet "refs/heads/$branch" >/dev/null; then
	echo "!! a local branch $branch exists already (a DRY_RUN's?) — delete it: git branch -D $branch" >&2; exit 1
fi
if git ls-remote --exit-code --heads origin "refs/heads/$branch" >/dev/null 2>&1; then
	echo "!! $branch is on origin already — its pull request is open, or was merged or closed without deleting the branch" >&2; exit 1
fi
git switch --quiet -c "$branch"
[ -f "$PLUGIN/CHANGELOG.md" ] || printf '# %s — changelog\n' "$PLUGIN" > "$PLUGIN/CHANGELOG.md"

sed -i "s/^version:.*/version: $version/" "$PLUGIN/plugin.yaml"

# The fragments in file-name order, each separated by a blank line.
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
        rest = lines[idx + 1:]
        while rest and rest[0] == "":
            rest.pop(0)
        lines[idx + 1:] = [""] + body.split("\n") + ([""] + rest if rest else [""])
else:
    if idx is None:
        # No release yet: the section goes after the title, at the end.
        while lines and lines[-1] == "":
            lines.pop()
        lines += [""] if lines else []
        idx = len(lines)
    lines[idx:idx] = [head, ""] + body.split("\n") + [""]
text = "\n".join(lines)
open(path, "w").write(text if text.endswith("\n") else text + "\n")
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
