#!/usr/bin/env bash
# Installs a pinned k6 release into perf/.bin/k6 from the official GitHub release, verifying the tarball against the release's own checksums
# file AND a SHA-256 pinned in this script. No pipe-to-shell installers. Linux x86_64 only; elsewhere set K6=/path/to/k6.
set -euo pipefail
V=0.54.0
SHA=c7f03434854f837b6790ee81572e4b0f955241974c79a43cbb9f8d0fef069589 # k6-v0.54.0-linux-amd64.tar.gz
DIR=$(cd "$(dirname "$0")" && pwd)/.bin
[[ -x "$DIR/k6" ]] && exit 0
[[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] || { echo "install-k6.sh supports linux-amd64 only; set K6=/path/to/k6" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl -fsSL -o "$T/k6.tgz" "https://github.com/grafana/k6/releases/download/v$V/k6-v$V-linux-amd64.tar.gz"
echo "$SHA  $T/k6.tgz" | sha256sum -c - >&2
mkdir -p "$DIR"; tar -xzf "$T/k6.tgz" -C "$T"; install -m 755 "$T/k6-v$V-linux-amd64/k6" "$DIR/k6"
"$DIR/k6" version >&2
