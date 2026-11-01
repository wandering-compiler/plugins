#!/usr/bin/env bash
# docs-only.sh <base-ref> — prints `true` when the pull request changes only
# Markdown, `false` otherwise. CI skips the plugin builds and the adoption test
# on `true`: no build, test or rendered release reads a word of the prose.
#
# Not docs-only:
#   - an empty diff (nothing to judge, so nothing is skipped);
#   - a deleted Markdown file, or one moved (--no-renames: a move is a delete):
#     a plugin's release form carries its SPEC.md and README.md, and rendering
#     it is part of what is skipped.
set -euo pipefail
BASE="${1:?usage: $0 <base-ref>}"
diff() { git -c core.quotePath=false diff --no-renames --name-only "$@" "$BASE"...HEAD; }
changed="$(diff)"
deleted="$(diff --diff-filter=D)"
if [ -z "$changed" ] || [ -n "$deleted" ] || grep -qv '\.md$' <<<"$changed"; then
	echo false
else
	echo true
fi
