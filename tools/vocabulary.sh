#!/usr/bin/env bash
# vocabulary.sh — print the directory holding the w17 proto vocabulary (its
# child is `w17/`), downloaded from the published SDK at the version pinned in
# tools/vocabulary-sdk-version.
#
# The vocabulary only RESOLVES imports while generating pb; it is never
# generated itself. Pinned so a regeneration is reproducible: bump the file when
# a plugin starts using something a newer SDK adds.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d ' \n' < "$HERE/vocabulary-sdk-version")"
WORK="$(mktemp -d -t w17-vocab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
(
	cd "$WORK"
	go mod init vocab >/dev/null 2>&1
	go get "github.com/wandering-compiler/sdk/go@$VERSION" >/dev/null 2>&1
	DIR="$(go list -m -f '{{.Dir}}' github.com/wandering-compiler/sdk/go)/proto"
	[ -d "$DIR/w17" ] || { echo "!! the SDK at $VERSION carries no proto/w17" >&2; exit 1; }
	echo "$DIR"
)
