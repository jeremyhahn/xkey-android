#!/usr/bin/env bash
# Build one devcontainer image, then point its tag at the ID the build wrote.
#
#   usage: scripts/build-image.sh [--keep-name] <tag> <iidfile|-> <docker build command...>
#
# The command is run with `-t <name> --iidfile <iidfile> .` appended.
#
# CUSTOMIZE (xkey-android): concurrent cold builds of one tag (main run 68429,
# job 319235). `docker build -t <tag>` names the image as its last step, and
# BuildKit's exporter names it by an update, then a create when the update
# finds no such name. A change to an image's inputs is a tag no runner has, so
# the jobs that build it at once on one daemon (image, lint-gates,
# integration) all miss, all create, and every create after the first fails
# `image "<tag>": already exists`, after a whole build.
#
# So no build names <tag>. A build is tagged <tag>-build-<random>, a name no
# other build writes, in <tag>'s repository (the reaper's family rule covers
# it), and writes its ID to <iidfile> (`-`: a temporary file). Then
# `docker tag` points <tag> at that ID; it replaces a name another job wrote,
# so the last job's build is the one <tag> names. A job takes only the ID its
# own build wrote, never one read back from <tag>. A failed build leaves <tag>
# where it was.
#
# --keep-name (IMAGE_FRESH=true, whose stages run on the ID in <iidfile>)
# keeps the build's own name, so the image keeps a name until its stages lease
# it even when a later build moves <tag> off it; the reaper removes the name
# REAP_IMAGE_MIN_AGE after its last use. Without it (a developer's make, a
# pull request's run, both of which read <tag> back) the build's name is
# removed once <tag> is set.
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

# CUSTOMIZE (xkey-android): concurrent re-tags of one tag (main run 69069, job
# 323125). The containerd image store re-tags a name as a delete, then a
# create, so when two jobs re-tag <tag> at once the second create can fail
# `image "<tag>": already exists`. Docker has no atomic re-tag, so that error
# alone is retried, up to tag_tries tries with a jittered back-off (under 10 s
# in all), each pointing <tag> at this build's own ID again. Any other error
# fails at once.
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
