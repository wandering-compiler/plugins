#!/usr/bin/env bash
# vocabulary.sh <plugin-dir> — print the directory holding the w17 proto
# vocabulary (its child is `w17/`) for one plugin.
#
# The vocabulary only RESOLVES imports while generating pb; it is never
# generated itself. It comes from the SDK version the plugin's own src/go.mod
# requires, so the pb and the Go it compiles against share one SDK. An SDK
# published before the vocabulary shipped with it (proto/w17) cannot supply it;
# then the version pinned in tools/vocabulary-sdk-version does. CI compiles and
# tests the plugin against its own go.mod either way, so a vocabulary that does
# not fit the code fails there.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${1:?usage: $0 <plugin-dir>}"
[ -f "$PLUGIN_DIR/src/go.mod" ] || { echo "!! $PLUGIN_DIR/src/go.mod not found" >&2; exit 1; }
DIR="$(cd "$PLUGIN_DIR/src" && go mod download github.com/wandering-compiler/sdk/go && go list -m -f '{{.Dir}}' github.com/wandering-compiler/sdk/go)/proto"
if [ ! -d "$DIR/w17" ]; then
	VERSION="$(tr -d ' \n' < "$HERE/vocabulary-sdk-version")"
	WORK="$(mktemp -d -t w17-vocab.XXXXXX)"
	trap 'rm -rf "$WORK"' EXIT
	DIR="$(cd "$WORK" && go mod init vocab >/dev/null 2>&1 && go get "github.com/wandering-compiler/sdk/go@$VERSION" >/dev/null 2>&1 && go list -m -f '{{.Dir}}' github.com/wandering-compiler/sdk/go)/proto"
	[ -d "$DIR/w17" ] || { echo "!! the SDK at $VERSION carries no proto/w17" >&2; exit 1; }
fi
echo "$DIR"
