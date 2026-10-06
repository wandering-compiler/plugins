#!/usr/bin/env bash
# gen-pb.sh — generate a plugin's src/gen/pb with plain buf.
#
# The same pb that `w17ctl plugin gen-pb` (and the console behind it) produces,
# from nothing but buf, docker, and the w17 proto vocabulary the SDK publishes.
# `make gen-pb` runs it for every plugin; CI runs it to check the committed pb.
#
#   usage: gen-pb.sh <plugin-dir> <vocabulary-dir>
#
#     plugin-dir       holds plugin.yaml + proto/ + src/
#     vocabulary-dir   the published w17 protos, i.e. the directory whose child
#                      is `w17/` — after `go mod download`, that is
#                      "$(go list -m -f '{{.Dir}}' github.com/wandering-compiler/sdk/go)/proto"
#
# Everything it does is reproducible by hand; it is written down because three of
# the steps are not guessable:
#
#   1. `@self/` is a w17 import placeholder, not a buf feature. It collapses to
#      the proto root for an author-facing build — a plain string replace.
#   2. every proto's go_package is FORCED to one value, so the whole plugin
#      flattens into a single `package pb`. That is buf managed mode, one override
#      per file, and the value derives from the manifest's `go_module`.
#   3. the vocabulary is RESOLVER-ONLY: staged so imports resolve, never
#      generated, or the plugin would ship its own copy of w17's own types.
set -euo pipefail

PLUGIN_DIR="${1:?usage: $0 <plugin-dir> <vocabulary-dir>}"
VOCAB_DIR="${2:?usage: $0 <plugin-dir> <vocabulary-dir>}"
# buf ALONE is not enough: the Go protoc plugins have to be on PATH inside the
# image, or `buf generate` reports `executable file not found`. The public
# bufbuild/buf image carries neither; tools/buf.Dockerfile adds them, pinned to
# what the committed pb headers declare (`make buf-image` builds it).
BUF_IMAGE="${BUF_IMAGE:?set BUF_IMAGE to a buf image carrying protoc-gen-go and protoc-gen-go-grpc — see the note above}"

command -v docker >/dev/null || { echo "!! docker required." >&2; exit 1; }
[ -f "$PLUGIN_DIR/plugin.yaml" ] || { echo "!! $PLUGIN_DIR holds no plugin.yaml" >&2; exit 1; }
[ -d "$VOCAB_DIR/w17" ] || { echo "!! $VOCAB_DIR holds no w17/ — point this at the SDK's proto dir" >&2; exit 1; }

# The canonical pb import path: `<go_module>/gen/pb`, mirroring
# pluginpbgen.CanonicalPbModule.
GO_MODULE="$(sed -n 's/^go_module:[[:space:]]*//p' "$PLUGIN_DIR/plugin.yaml" | head -1 | tr -d '"'"'"' ')"
[ -n "$GO_MODULE" ] || { echo "!! plugin.yaml declares no go_module — the pb path derives from it" >&2; exit 1; }
CANONICAL="$GO_MODULE/gen/pb"

WORK="$(mktemp -d -t w17-plugin-genpb.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/proto"

# 1 + 3. the plugin's protos with @self collapsed, then the vocabulary beside
#        them. Order matters only in that the vocabulary must not overwrite a
#        plugin file, which it cannot: w17/ is its own subtree.
( cd "$PLUGIN_DIR/proto" && find . -name '*.proto' -print0 ) | while IFS= read -r -d '' rel; do
	mkdir -p "$WORK/proto/$(dirname "$rel")"
	sed 's|@self/||g' "$PLUGIN_DIR/proto/$rel" > "$WORK/proto/$rel"
done
cp -R "$VOCAB_DIR/w17" "$WORK/proto/w17"

# 2. managed mode, one go_package override per PLUGIN proto — never for the
#    vocabulary, which keeps its own.
{
	echo "version: v2"
	echo "managed:"
	echo "  enabled: true"
	echo "  override:"
	( cd "$WORK/proto" && find . -name '*.proto' ! -path './w17/*' | sed 's|^\./||' | sort ) |
		while read -r rel; do
			echo "    - file_option: go_package"
			echo "      path: \"$rel\""
			echo "      value: \"$CANONICAL\""
		done
	echo "plugins:"
	echo "  - local: protoc-gen-go"
	echo "    out: gen"
	echo "    opt:"
	echo "      - module=$CANONICAL"
	echo "  - local: protoc-gen-go-grpc"
	echo "    out: gen"
	echo "    opt:"
	echo "      - module=$CANONICAL"
	echo "      - require_unimplemented_servers=false"
} > "$WORK/buf.gen.yaml"
printf 'version: v2\nmodules:\n  - path: proto\n' > "$WORK/buf.yaml"

# Only the plugin's own files are TARGETS; the vocabulary is there to resolve.
# Portable array fill. `mapfile` is bash 4, and macOS still ships 3.2 — a tool
# written for any author's machine cannot assume a newer shell.
TARGETS=()
while IFS= read -r rel; do
	TARGETS+=("$rel")
done < <( cd "$WORK/proto" && find . -name '*.proto' ! -path './w17/*' | sed 's|^\./|proto/|' | sort )
[ "${#TARGETS[@]}" -gt 0 ] || { echo "!! the plugin declares no proto files" >&2; exit 1; }

# One `--path` FLAG per target, as separate argv entries. Joining them into a
# single string ("--path proto/a") makes buf see one unknown argument, and the
# run that follows a swallowed failure generates the vocabulary too.
PATH_ARGS=()
for t in "${TARGETS[@]}"; do PATH_ARGS+=(--path "$t"); done

docker run --rm \
	-u "$(id -u):$(id -g)" \
	-v "$WORK":/workspace -w /workspace \
	-e HOME=/tmp \
	"$BUF_IMAGE" \
	generate --template buf.gen.yaml "${PATH_ARGS[@]}"

# `module=<canonical>` tells protoc-gen-go to STRIP that prefix from the output
# path, so the files land directly under the `out:` directory rather than under
# gen/<canonical>/. Looking for them at the prefixed path finds nothing, and the
# run reads as a silent no-op.
OUT="$WORK/gen"
produced="$(find "$OUT" -name '*.pb.go' 2>/dev/null | wc -l | tr -d ' ')"
[ "$produced" -gt 0 ] || { echo "!! buf produced no pb under $OUT" >&2; exit 1; }

# Copy FIRST, into a sibling, then swap. Deleting the author's pb and then
# copying means a failed copy — a full disk, a permission — leaves them with no pb
# at all, and `set -e` aborts after the delete rather than before it.
STAGE="$PLUGIN_DIR/src/gen/.pb.new"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$OUT"/*.pb.go "$STAGE/"
mkdir -p "$PLUGIN_DIR/src/gen/pb"
find "$PLUGIN_DIR/src/gen/pb" -name '*.pb.go' -delete
cp "$STAGE"/*.pb.go "$PLUGIN_DIR/src/gen/pb/"
rm -rf "$STAGE"
echo "gen-pb: wrote $produced file(s) to $PLUGIN_DIR/src/gen/pb"
