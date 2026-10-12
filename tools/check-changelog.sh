#!/usr/bin/env bash
# check-changelog.sh <base-ref> — a pull request that changes a plugin says
# what changed, in a fragment: <plugin>/changes/<name>.md, a `### ` heading
# and a few lines for the plugin's users. tools/release-pr.sh collects the
# fragments into the CHANGELOG when the plugin is released, so pull requests
# never edit the same CHANGELOG lines and never conflict over them.
#
# Exempt:
#   - a release pull request (branch release/<plugin>-v…), which collects them;
#   - a pull request labelled no-changelog (CI passes NO_CHANGELOG=1): a change
#     a plugin's user cannot notice, such as tests or comments.
set -euo pipefail
BASE="${1:?usage: $0 <base-ref>}"
case "${HEAD_REF:-}" in release/*) echo "release pull request: fragments are collected, not added"; exit 0 ;; esac
[ "${NO_CHANGELOG:-0}" = 1 ] && { echo "labelled no-changelog"; exit 0; }

changed="$(git diff --name-only "$BASE"...HEAD)"
bad=0
for m in */plugin.yaml; do
	p="${m%/plugin.yaml}"
	touched="$(grep "^$p/" <<<"$changed" | grep -v "^$p/changes/" || true)"
	[ -n "$touched" ] || continue
	if grep -q "^$p/CHANGELOG.md$" <<<"$touched"; then
		echo "!! $p/CHANGELOG.md is edited directly: add $p/changes/<name>.md instead (the release collects it)"
		bad=1
	fi
	added="$(git diff --name-only --diff-filter=A "$BASE"...HEAD -- "$p/changes/" | grep '\.md$' || true)"
	if [ -z "$added" ]; then
		echo "!! $p changed and no fragment was added: add $p/changes/<name>.md, or label the pull request no-changelog"
		bad=1
		continue
	fi
	for f in $added; do
		head -1 "$f" | grep -q '^### ' || { echo "!! $f must start with a '### ' heading"; bad=1; }
	done
done
exit $bad
