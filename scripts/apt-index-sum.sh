#!/usr/bin/env bash
# Prints one sha256 over the Debian package index of BASE_IMAGE, for APT_INDEX_SUM; exits 1 if it cannot be read. Usage: scripts/apt-index-sum.sh
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
