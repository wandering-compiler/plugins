#!/usr/bin/env bash
# w17ctl.sh — print the path of the w17ctl pinned in tools/w17ctl-version,
# installing it into a cache on first use.
#
# The checks render a plugin the way a consumer's w17ctl will (check-render,
# check-published-tests), so they use exactly this binary, never whatever
# `w17ctl` happens to be on PATH. The release workflow signs with it too;
# signing does not depend on the version (it digests the committed tree and
# asks the console).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d ' \n' < "$HERE/w17ctl-version")"
DIR="${XDG_CACHE_HOME:-$HOME/.cache}/w17-plugins/w17ctl-$VERSION"
if [ ! -x "$DIR/w17ctl" ]; then
	command -v go >/dev/null || { echo "!! Go is needed to install the pinned w17ctl $VERSION" >&2; exit 1; }
	mkdir -p "$DIR"
	GOBIN="$DIR" GOFLAGS=-buildvcs=false go install "github.com/wandering-compiler/w17ctl@$VERSION" >&2
fi
echo "$DIR/w17ctl"
