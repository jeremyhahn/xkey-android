#!/usr/bin/env bash
# Build under a unique name, then point <tag> at the built ID, so concurrent builds of one tag succeed. Usage: scripts/build-image.sh [--keep-name] <tag> <iidfile|-> <docker build command...>
set -euo pipefail

keep=false
if [ "${1:-}" = --keep-name ]; then
	keep=true
	shift
fi
if [ $# -lt 3 ]; then
	echo "usage: $0 [--keep-name] <tag> <iidfile|-> <docker build command...>" >&2
	exit 2
fi
tag=$1 iid=$2
shift 2

case ${tag##*/} in
*:*) name="${tag}-build-" ;;
*) name="${tag}:build-" ;;
esac
name+=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')

tmp=
if [ "${iid}" = - ]; then
	tmp=$(mktemp)
	iid=${tmp}
fi
trap '[ -z "${tmp}" ] || rm -f "${tmp}"' EXIT

if ! "$@" -t "${name}" --iidfile "${iid}" .; then
	docker image rm "${name}" > /dev/null 2>&1 || true
	exit 1
fi
id=$(cat "${iid}")
if ! [[ ${id} =~ ^sha256:[0-9a-f]{64}$ ]]; then
	echo "$0: the build of ${tag} wrote '${id}' to ${iid}, not an image ID" >&2
	exit 1
fi
drop_name() {
	[ "${keep}" = true ] || docker image rm "${name}" > /dev/null || echo "$0: could not remove the build's own name ${name}" >&2
}

# A concurrent re-tag can fail `already exists`; retry only that, with jittered back-off.
tag_tries=5
backoff_ms=${BUILD_IMAGE_TAG_BACKOFF_MS:-500}
try=1
while ! err=$(docker tag "${id}" "${tag}" 2>&1); do
	printf '%s\n' "${err}" >&2
	case ${err} in
	*"already exists"*) ;;
	*) drop_name; exit 1 ;;
	esac
	if [ "${try}" -ge "${tag_tries}" ]; then
		echo "$0: could not point ${tag} at ${id}: a concurrent re-tag collided ${tag_tries} times" >&2
		drop_name
		exit 1
	fi
	ms=$((backoff_ms * try + RANDOM % (2 * backoff_ms)))
	sleep "$((ms / 1000)).$(printf '%03d' $((ms % 1000)))"
	try=$((try + 1))
done
drop_name
