#!/usr/bin/env bash
# Remove this repo's stopped CI leftovers on the runner host.
#
#   usage: scripts/reap-stale-ci-stacks.sh <prefix> [min-age-seconds]
#
# For a runner host that outlives its jobs (a self-hosted runner or a
# developer machine); a GitHub-hosted runner is fresh per job and needs none
# of it. An integration job's `if: always()` teardown runs only while the job
# process lives. When the host or its Docker daemon dies mid-job, the job is
# gone and so is its teardown: the compose stack stays behind, exited, with
# its networks and volumes. Nothing else removes them.
#
# What it removes, on the Docker host the job talks to:
#   - a compose project (label com.docker.compose.project) whose name starts
#     with <prefix>, when EVERY container in it is stale; then the project's
#     networks and volumes (same label);
#   - a container outside compose whose name starts with <prefix>, when stale,
#     with its anonymous volumes.
#   - images. The integration image is named by its content, <prefix>it:<hash>
#     (`make -s it-image`), and every job and run of that tree on this host
#     reuses it, so no job removes it. This removes a <prefix>it image idle
#     for at least REAP_IMAGE_MIN_AGE seconds, default 7200 (2 h: the longest
#     full-tier run plus headroom), so an image a run still needs is not old
#     enough. `docker image rm` without force refuses an image a container
#     (running or stopped) uses, so a live stack's image is never removed.
#     A job may hold a lease on an image: a created, never started container
#     named <prefix>lease-<run>-.... A lease a dead job leaves is stale like
#     any other container outside compose, and goes after <min-age-seconds>;
#     its image goes on the reap after that.
#   - An image's age runs from the later of its `.Created` and its last tag
#     time (`.Metadata.LastTagTime`). A rebuild from a full cache keeps the
#     old `.Created` but re-tags the image, so creation time alone would make
#     a just-rebuilt image look stale to a parallel job's reaper.
#   - REAP_IMAGE_REPOS (<repo>-toolchain, whose tags are <hash> and
#     pr-<hash>) names more image repositories to reap by the same rule as
#     <prefix>it. Each family's untagged images go too: a trusted run builds
#     fresh every time (Makefile IMAGE_FRESH), so its build moves the tag off
#     the last one, which no tag lookup finds again. `make docker-build`
#     labels every image ci.image.repository=<repository>, and an untagged
#     image is reaped only under one of these names.
#   - An image is removed only when no container, running or created, uses
#     its ID, checked before the removal: `docker image rm <tag>` of an image
#     with two tags (a pr- tag a run took from the trusted one) only untags
#     it, even while a lease holds it. A run's reuse of a tag moves its tag
#     time (the Makefile re-tags it), so the age is the image's last use: an
#     image in use is kept, an idle one goes REAP_IMAGE_MIN_AGE after its
#     last use. An old trusted tag is only a cache (no trusted run reuses
#     it), so age is its only test. The log line names the lease or stage
#     that keeps an image.
#   - A lease (any <prefix> container) may carry ci.lease.expires, a Unix
#     time: past it, the lease is stale even before <min-age-seconds>.
#   - The image loop runs under the daemon's image lock, so a job cannot take
#     a lease between the reaper's in-use check and its `docker image rm`.
#     The lock is a created, never-started container named
#     <prefix>image-lock, from <prefix>image-lock:base (an empty image this
#     script imports when it is missing); the daemon refuses a second
#     container of that name, so there is one holder at a time. A lock
#     created more than 600 s ago is a dead holder's and is removed by its
#     id. The reaper waits up to REAP_LOCK_WAIT seconds (default 60) for it,
#     and without it removes no image that run. The in-use list is read after
#     the lock is taken. The tag time is read as a string: on Docker 29
#     `{{.Metadata.LastTagTime.Unix}}` is a template error, and an inspect
#     without an id would have removed the tag whatever its age or lease. An
#     image the inspect gives no id for is kept.
#
# Stale: exited or dead and finished at least <min-age-seconds> ago, or
# created and never started at least that long ago. A project with any
# container running, paused, restarting or removing is never touched.
#
# <min-age-seconds> defaults to 11100: a 3 h job timeout plus 5 min,
# so no job that could still own the stack is alive. Pass the job's own
# timeout-minutes * 60 plus a margin only if you know every runner's timeout.
#
# The prefix is the repo's own (`xkey-android-ci-`): the name the job
# gives its compose project, without the run id. Never a prefix another repo's
# projects could start with.
#
# A failed removal is reported and skipped: the reaper never fails the job.
# REAP_DRY_RUN=1 prints what would be removed and removes nothing.
set -u

prefix=${1:-}
min_age=${2:-11100}
case $prefix in
  '' | *[!A-Za-z0-9_.-]*) echo "usage: $0 <prefix [A-Za-z0-9_.-]> [min-age-seconds]" >&2; exit 2 ;;
esac
case $min_age in
  '' | *[!0-9]*) echo "min-age-seconds must be a number: $min_age" >&2; exit 2 ;;
esac
image_min_age=${REAP_IMAGE_MIN_AGE:-7200}
case $image_min_age in
  '' | *[!0-9]*) echo "REAP_IMAGE_MIN_AGE must be a number: $image_min_age" >&2; exit 2 ;;
esac
# The image families (above).
image_repos="${prefix}it ${REAP_IMAGE_REPOS:-}"
for repo in ${REAP_IMAGE_REPOS:-}; do
  case $repo in
    *[!a-z0-9_./-]*) echo "REAP_IMAGE_REPOS: not an image repository name: $repo" >&2; exit 2 ;;
  esac
done

lock_wait=${REAP_LOCK_WAIT:-60}
case $lock_wait in
  '' | *[!0-9]*) echo "REAP_LOCK_WAIT must be a number: $lock_wait" >&2; exit 2 ;;
esac

now=$(date +%s)

# run <command...>: the command, or only its echo under REAP_DRY_RUN=1.
run() {
  if [ "${REAP_DRY_RUN:-0}" = 1 ]; then echo "dry   $*"; else "$@" >/dev/null; fi
}

# stale <container>: 0 when the container is stale (as above), 1 otherwise.
stale() {
  local state finished created expires t
  read -r state finished created expires < <(docker inspect \
    -f '{{.State.Status}} {{.State.FinishedAt}} {{.Created}} {{index .Config.Labels "ci.lease.expires"}}' "$1" 2>/dev/null) || return 1
  case $state in
    exited | dead) t=$finished ;;
    created) t=$created ;;
    *) return 1 ;;
  esac
  t=$(date -d "$t" +%s 2>/dev/null) || return 1
  # A lease past its expiry (above).
  case $expires in
    '' | *[!0-9]*) ;;
    *) [ "$now" -lt "$expires" ] || return 0 ;;
  esac
  [ $((now - t)) -ge "$min_age" ]
}

# image_lock: take the daemon's image lock (above), waiting up to
# REAP_LOCK_WAIT seconds; 1 when it is not taken. image_unlock drops it.
lock="${prefix}image-lock"
lock_id=
image_lock() {
  local base="$lock:base" held at t i
  for ((i = 0; i < lock_wait; i++)); do
    docker image inspect "$base" >/dev/null 2>&1 ||
      head -c 1024 /dev/zero | docker import - "$base" >/dev/null 2>&1
    lock_id=$(docker create --pull never --name "$lock" "$base" true 2>/dev/null) && return 0
    lock_id=
    if read -r held at < <(docker inspect -f '{{.Id}} {{.Created}}' "$lock" 2>/dev/null) &&
      t=$(date -d "$at" +%s 2>/dev/null) && [ $(($(date +%s) - t)) -ge 600 ]; then
      echo "lock  removing the stale $lock (created $at)"
      docker rm "$held" >/dev/null 2>&1
      continue
    fi
    sleep 1
  done
  return 1
}
image_unlock() {
  [ -z "$lock_id" ] || docker rm "$lock_id" >/dev/null 2>&1
  lock_id=
}
trap image_unlock EXIT

reaped=0

# Compose projects.
for project in $(docker ps -a --filter label=com.docker.compose.project \
    --format '{{.Label "com.docker.compose.project"}}' | sort -u); do
  case $project in "$prefix"*) ;; *) continue ;; esac
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  keep=0
  for id in $ids; do stale "$id" || { keep=1; break; }; done
  if [ "$keep" = 1 ]; then
    echo "keep  $project (a container is live or stopped within ${min_age}s)"
    continue
  fi
  # shellcheck disable=SC2086 # one id per word
  set -- $ids
  echo "reap  $project: $# container(s)"
  run docker rm -v "$@" || echo "warn  $project: container removal failed"
  for net in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker network rm "$net" || echo "warn  $project: network $net not removed"
  done
  for vol in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker volume rm "$vol" || echo "warn  $project: volume $vol not removed"
  done
  reaped=$((reaped + 1))
done

# Containers outside compose.
docker ps -a --filter "name=^$prefix" \
    --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' |
  while read -r id name project; do
    [ -z "$project" ] || continue
    case $name in "$prefix"*) ;; *) continue ;; esac
    if stale "$id"; then
      echo "reap  container $name"
      run docker rm -v "$id" || echo "warn  container $name not removed"
    fi
  done

# Content-addressed images (above): every family in image_repos, their untagged images, and the in-use check (above).
images=0
in_use=' '

# reap_image <ref>: remove the image <ref> (a tag, or an untagged image's ID)
# when no container uses it and its last use is REAP_IMAGE_MIN_AGE ago.
reap_image() {
  local id='' created='' tagged t
  read -r id created < <(docker image inspect -f '{{.Id}} {{.Created}}' "$1" 2>/dev/null)
  if [ -z "$id" ] || [ -z "$created" ]; then
    echo "keep  image $1 (docker image inspect gave no id)"
    return 0
  fi
  case $in_use in *" $id "*)
    echo "keep  image $1 (a container uses it: a lease or a live stage)"
    return 0 ;;
  esac
  t=$(date -d "$created" +%s 2>/dev/null) || return 0
  # Go prints the tag time as "2026-10-21 00:35:47.26 +0000 UTC"; date -d
  # takes it without the fraction and the zone name. A never-tagged image
  # reports the zero time, a large negative number.
  tagged=$(docker image inspect -f '{{.Metadata.LastTagTime}}' "$1" 2>/dev/null | sed -E 's/\.[0-9]+//; s/ [A-Z]+$//')
  tagged=$(date -d "$tagged" +%s 2>/dev/null) || tagged=
  case $tagged in ''|*[!0-9]*) ;; *) [ "$tagged" -le "$t" ] || t=$tagged ;; esac
  if [ $((now - t)) -lt "$image_min_age" ]; then
    echo "keep  image $1 (created or tagged within ${image_min_age}s)"
    return 0
  fi
  echo "reap  image $1"
  if run docker image rm "$1"; then images=$((images + 1)); else echo "warn  image $1 not removed (in use?)"; fi
}

if [ "${REAP_DRY_RUN:-0}" = 1 ] || image_lock; then
  # The image IDs a container uses (a lease, a stage, a stack), read under
  # the lock and after the stale leases went above.
  in_use=" $(docker ps -aq | xargs -r docker inspect -f '{{.Image}}' 2>/dev/null | tr '\n' ' ') "
  for repo in $image_repos; do
    for ref in $(docker images --filter "reference=$repo" --format '{{.Repository}}:{{.Tag}}'); do
      case $ref in "$repo:"*) reap_image "$ref" ;; esac
    done
    for id in $(docker images -q --no-trunc --filter dangling=true --filter "label=ci.image.repository=$repo"); do
      reap_image "$id"
    done
  done
else
  echo "keep  every image (the image lock was not free within ${lock_wait}s)"
fi
image_unlock

if [ "${REAP_DRY_RUN:-0}" = 1 ]; then done_as="would be removed"; else done_as=removed; fi
echo "reaper: $reaped compose project(s) and $images image(s) $done_as for prefix '$prefix'"
exit 0
