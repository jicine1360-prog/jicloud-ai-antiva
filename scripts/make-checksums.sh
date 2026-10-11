#!/usr/bin/env sh
# make-checksums.sh <dist-subdir>
# Writes dist/<subdir>/SHA-256SUMS with relative paths (safe to distribute).
set -eu

DIR="${1:?usage: make-checksums.sh <dist-subdir>}"

cd "$DIR"
find . -type f ! -name SHA-256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA-256SUMS
printf '%s\n' "checksums written: $DIR/SHA-256SUMS"