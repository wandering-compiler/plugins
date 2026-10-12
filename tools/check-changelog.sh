#!/usr/bin/env bash
# check-changelog.sh <base-ref> — a pull request that changes a plugin says
# what changed, in a fragment: <plugin>/changes/<name>.md, a `### ` heading
# and a few lines for the plugin's users. tools/release-pr.sh collects the
# fragments into the CHANGELOG when the plugin is released, so pull requests
# never edit the same CHANGELOG lines and never conflict over them.
#
# Exempt:
#   - a release pull request (branch release/<plugin>-v0.1.0-rc.N), which
#     collects them. A branch name is anyone's to choose, so the exemption
#     holds only for the shape tools/release-pr.sh produces: the manifest
#     says that version, and the pull request changes <plugin>/plugin.yaml and
#     <plugin>/CHANGELOG.md and deletes fragments of that plugin, nothing else;
#   - a pull request labelled no-changelog (CI passes NO_CHANGELOG=1): a change
#     a plugin's user cannot notice, such as tests or comments.
set -euo pipefail
BASE="${1:?usage: $0 <base-ref>}"
# --no-renames: a file moved out of a plugin changes that plugin too, and a
# fragment that resembles a deleted one is still an added fragment.
# core.quotePath=false: a name with a non-ASCII character comes out as is.
changed_files() { git -c core.quotePath=false diff --no-renames --name-only "$@" "$BASE"...HEAD; }
changed="$(changed_files)"

if [[ "${HEAD_REF:-}" =~ ^release/(.+)-v(0\.1\.0-rc\.[0-9]+)$ ]] && [ -f "${BASH_REMATCH[1]}/plugin.yaml" ]; then
	p="${BASH_REMATCH[1]}" version="${BASH_REMATCH[2]}"
	manifest="$(sed -n 's/^version:[[:space:]]*//p' "$p/plugin.yaml" | head -1 | tr -d "\"' ")"
	[ "$manifest" = "$version" ] || { echo "!! $p/plugin.yaml says $manifest, the branch releases $version"; exit 1; }
	deleted="$(changed_files --diff-filter=D)"
	other="$(grep -vxF -e "$p/plugin.yaml" -e "$p/CHANGELOG.md" <<<"$changed" || true)"
	stray=""
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		case "$f" in "$p"/changes/*.md) grep -qxF -- "$f" <<<"$deleted" && continue ;; esac
		stray+="$f"$'\n'
	done <<<"$other"
	if [ -n "$stray" ]; then
		echo "!! a release pull request changes $p/plugin.yaml and $p/CHANGELOG.md and deletes $p/changes/*.md, nothing else; this one also changes:"
		printf '%s' "$stray"
		exit 1
	fi
	echo "release pull request for $p v$version: fragments are collected, not added"
	exit 0
fi
[ "${NO_CHANGELOG:-0}" = 1 ] && { echo "labelled no-changelog"; exit 0; }

bad=0
for m in */plugin.yaml; do
	p="${m%/plugin.yaml}"
	touched="$(grep "^$p/" <<<"$changed" | grep -v "^$p/changes/" || true)"
	[ -n "$touched" ] || continue
	if grep -qxF "$p/CHANGELOG.md" <<<"$touched"; then
		echo "!! $p/CHANGELOG.md is edited directly: add $p/changes/<name>.md instead (the release collects it)"
		bad=1
	fi
	# Only <plugin>/changes/<name>.md is collected: one in a subdirectory, or
	# without .md, would never reach the CHANGELOG.
	added="$(changed_files --diff-filter=A | grep -E "^$p/changes/[^/]+\.md$" || true)"
	if [ -z "$added" ]; then
		echo "!! $p changed and no fragment was added: add $p/changes/<name>.md, or label the pull request no-changelog"
		bad=1
		continue
	fi
	while IFS= read -r f; do
		head -1 "$f" | grep -q '^### ' || { echo "!! $f must start with a '### ' heading"; bad=1; }
	done <<<"$added"
done
exit $bad
