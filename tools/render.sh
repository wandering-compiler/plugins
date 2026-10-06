#!/usr/bin/env bash
# render.sh — turn ONE plugin's author tree into the installable form.
#
# The counterpart to gen-pb.sh. A release commit holds this form, never the
# author tree: `make release` renders, signs and tags it (see RELEASING.md).
#
#   usage: render.sh <plugin-dir> <dest-dir>
#
# What the installable form is, and why it is not the author tree:
#
#   · every Go file — go.mod and go.sum included — is suffixed `.src`. A vendored
#     plugin's sources are INERT DATA in a consumer's project until staging
#     rewrites their import paths, and a live go.mod under
#     <project>/proto/plugins/<name>/src would make the plugin a module inside the
#     consumer's own build. The client strips the suffix when it places the tree.
#   · TESTS are carried, suffixed like the rest. The registry is public and a
#     plugin whose tests are invisible asks to be trusted on its word; the client
#     drops them when it places the tree, because nothing in a consumer runs them.
#   · `src/gen/pb` is NOT carried. It is generated output — a consumer's codegen
#     emits its own per activation, and an author regenerates it with gen-pb.sh.
set -euo pipefail

PLUGIN_DIR="${1:?usage: $0 <plugin-dir> <dest-dir>}"
DEST="${2:?usage: $0 <plugin-dir> <dest-dir>}"

[ -f "$PLUGIN_DIR/plugin.yaml" ] || { echo "!! $PLUGIN_DIR holds no plugin.yaml" >&2; exit 1; }
NAME="$(sed -n 's/^name:[[:space:]]*//p' "$PLUGIN_DIR/plugin.yaml" | head -1 | tr -d '"'"'"' ')"
[ -n "$NAME" ] || { echo "!! plugin.yaml declares no name" >&2; exit 1; }

OUT="$DEST/$NAME"
rm -rf "$OUT"
mkdir -p "$OUT"

cp "$PLUGIN_DIR/plugin.yaml" "$OUT/"
[ -f "$PLUGIN_DIR/README.md" ] && cp "$PLUGIN_DIR/README.md" "$OUT/"
if [ -d "$PLUGIN_DIR/proto" ]; then
	mkdir -p "$OUT/proto"
	cp -R "$PLUGIN_DIR/proto/." "$OUT/proto/"
fi

if [ -d "$PLUGIN_DIR/src" ]; then
	mkdir -p "$OUT/src"
	for f in go.mod go.sum; do
		[ -f "$PLUGIN_DIR/src/$f" ] && cp "$PLUGIN_DIR/src/$f" "$OUT/src/$f.src"
	done
	[ -f "$PLUGIN_DIR/src/.gitignore" ] && cp "$PLUGIN_DIR/src/.gitignore" "$OUT/src/.gitignore"
	# Every .go — tests included — except the generated pb.
	( cd "$PLUGIN_DIR/src" && find . -type f -name '*.go' ! -path './gen/pb/*' -print0 ) |
		while IFS= read -r -d '' rel; do
			mkdir -p "$OUT/src/$(dirname "$rel")"
			cp "$PLUGIN_DIR/src/$rel" "$OUT/src/$rel.src"
		done
fi

# The inertness rule, asserted rather than assumed: a live .go or go.mod under
# src/ would make the plugin a module inside every consumer's build, which is the
# whole reason for the suffix.
if find "$OUT/src" -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) 2>/dev/null | grep -q .; then
	echo "!! $NAME rendered LIVE Go sources under src/ — they must be inert (.src):" >&2
	find "$OUT/src" -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) | sed 's/^/     /' >&2
	exit 1
fi

files="$(find "$OUT" -type f | wc -l | tr -d ' ')"
tests="$(find "$OUT" -name '*_test.go.src' | wc -l | tr -d ' ')"
echo "render: $NAME → $OUT ($files file(s), $tests test file(s), pb excluded)"
