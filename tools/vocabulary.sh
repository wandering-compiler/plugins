#!/usr/bin/env bash
# vocabulary.sh <plugin-dir> — print the directory holding the w17 proto
# vocabulary (its child is `w17/`) for one plugin: the published SDK at the
# version the plugin's own src/go.mod requires.
#
# The vocabulary only RESOLVES imports while generating pb; it is never
# generated itself. Taken from the plugin's own requirement so the pb and the Go
# it compiles against come from one SDK version — bump the SDK in go.mod and the
# vocabulary follows.
set -euo pipefail
PLUGIN_DIR="${1:?usage: $0 <plugin-dir>}"
[ -f "$PLUGIN_DIR/src/go.mod" ] || { echo "!! $PLUGIN_DIR/src/go.mod not found — the SDK version comes from it" >&2; exit 1; }
cd "$PLUGIN_DIR/src"
go mod download github.com/wandering-compiler/sdk/go
DIR="$(go list -m -f '{{.Dir}}' github.com/wandering-compiler/sdk/go)/proto"
[ -d "$DIR/w17" ] || {
	echo "!! the SDK $(go list -m github.com/wandering-compiler/sdk/go) carries no proto/w17 — require a newer one in $PLUGIN_DIR/src/go.mod" >&2
	exit 1
}
echo "$DIR"
