#!/usr/bin/env bash
# apt-index-sum: the Debian counterpart of apk-index-sum.sh — one checksum
# of the Debian package index the devcontainer build resolves against.
#
# This repository's base is Debian (BASE_IMAGE in scripts/tool-pins.sh), so
# apk-index-sum.sh, which ships unchanged, prints `none`, and a Debian
# security fix would not change the integration image's tag. This script is
# the Debian mirror of it. Each ci.yml job that names the integration image
# puts the printed value in APT_INDEX_SUM, which the image's content tag
# hashes (`make -s it-image`, image-tag.sh) and which its build takes as a
# build argument, so the Dockerfile's `integration` stage runs
# `apt-get upgrade` again and ships the fixed packages.
#
# Usage: scripts/apt-index-sum.sh
#   Runs the pinned BASE_IMAGE from scripts/tool-pins.sh once, as root with
#   every capability dropped but the ones apt needs (its fetch methods run as
#   _apt), and `--rm`. In it `apt-get update` fetches the indexes of the
#   image's own sources. DEVCACHE_APT_PROXY, when set, is the proxy, as for
#   the image build (Makefile DOCKER_BUILD): the sum then describes the index
#   the build itself reads through it. CI sets none.
#
# Prints a sha256 over the name and sha256 of each /var/lib/apt/lists
# *_Packages* file, sorted by name. Exits 1 when the image cannot be resolved,
# run or updated, or has no _Packages file: a missing index is never a pass,
# since the image build then cannot resolve its packages either.
set -euo pipefail

fail() {
  echo "::error::apt-index-sum: $*" >&2
  exit 1
}

pins="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tool-pins.sh"
[ -f "$pins" ] || fail "no $pins"
# shellcheck source-path=SCRIPTDIR source=tool-pins.sh
img=$(. "$pins" && printf '%s' "${BASE_IMAGE:-}")
[ -n "$img" ] || fail "no BASE_IMAGE in $pins"
command -v docker > /dev/null 2>&1 || fail "docker not found on PATH"

# Runs in the base image.
# shellcheck disable=SC2016 # expanded by the container's shell
probe='export LC_ALL=C
command -v apt-get >/dev/null 2>&1 || exit 2
if [ -n "${APT_PROXY:-}" ]; then echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/01proxy || exit 5; fi
apt-get update -qq -o APT::Update::Error-Mode=any >/dev/null || exit 3
cd /var/lib/apt/lists || exit 4
set -- *_Packages*
[ -f "$1" ] || exit 4
sha256sum "$@" | sort -k2'

out=$(docker run --rm --pull missing --network bridge --user 0 \
        --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
        --cap-add SETUID --cap-add SETGID \
        --security-opt no-new-privileges -e "APT_PROXY=${DEVCACHE_APT_PROXY:-}" \
        --entrypoint /bin/sh "$img" -c "$probe") ||
  fail "reading the Debian package index of $img failed (exit $?)"

[ -n "$out" ] || fail "$img has no _Packages file"
n=0
while read -r sum file; do
  [[ $sum =~ ^[0-9a-f]{64}$ && $file == *_Packages* ]] || fail "$img printed '$sum $file', not a _Packages checksum"
  n=$((n + 1))
done <<< "$out"
echo "apt-index-sum: $img: $n index file(s)" >&2

printf '%s\n' "$out" | sha256sum | cut -d' ' -f1
