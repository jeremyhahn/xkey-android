#!/usr/bin/env bash
# Run a command in the toolchain image against a COPY of the checkout.
#
#   usage: scripts/in-toolchain-image.sh <image> <command...>
#   e.g.   scripts/in-toolchain-image.sh xkey-android-toolchain:abc make build
#   <image> is a tag or an image ID (sha256:...); CI passes the ID.
#
# How CI runs a stage in the devcontainer image. A
# CI runner reaches its Docker daemon through a socket, so a bind mount would
# resolve on the daemon's host, where the checkout does not exist. This
# creates the container, streams the checkout into it (`.git` included: the
# releasability tests read it) owned by the image's non-root user, then starts
# it and returns the command's exit status. It works the same against a local
# daemon; on a workstation `make docker-run CMD=...` (bind mount) is the
# shorter path.
#
# The container keeps the integration service's posture where a copy-in allows
# it: every capability dropped, no-new-privileges, the same ulimits and pid
# bound, a non-root user, no network. The root filesystem is writable only
# because `docker cp` cannot write into a read-only one.
#
# IN_IMAGE_NETWORK=bridge gives the container a network, for the stages that
# must reach one: `make deps-check` asks the module proxy for the newest
# releases, and `make security` fetches the vulnerability databases. Only then
# is GOPROXY set to the module proxy alone (no fallback to a module's origin
# repository), a writable module cache mounted (below; /tmp/gomodcache
# with CI_CACHE=off), and the forge credentials passed through, by NAME from
# this environment (the four variables the runner injects), so no token ever
# appears on a command line.
#
# The caches live in named volumes on the daemon's host, never in the container's
# writable layer or its 3 GB /tmp: GOCACHE at /cache/gobuild and
# GOLANGCI_LINT_CACHE at /cache/golangci for every stage, and, for a bridge
# stage, GOMODCACHE at /cache/gomod (a no-network stage keeps the image's own
# read-only module cache, so it still proves the image works offline). The
# volumes are <CI_STACK_PREFIX>cache-<class>-{gobuild,golangci,gomod}, one set
# per repo, trust class and daemon host, kept across jobs. CI_CACHE_CLASS
# (default pr) is `main` only for a push to main, so a pull request never
# writes a cache that main's build reads. A new volume's root is given to
# IN_IMAGE_UID by a helper container holding CHOWN and nothing else.
# scripts/trim-ci-caches.sh bounds their size. CI_CACHE=off mounts none.
#
# The stage runs in this sibling container, so the sibling holds the job slot's
# CPU bound. The job container's cgroup cpu.max gives it (rounded up; nproc
# when the job has no quota; IN_IMAGE_CPUS overrides), and the sibling gets
# --cpus N with GOMAXPROCS=N and GOFLAGS=-p=N. golangci-lint's default
# concurrency follows the container CPU quota, so lint takes N with no flag.
# A 4-CPU runner gives 4; never a hardcoded number.
#
# The container is named <CI_STACK_PREFIX>tc-<pid>-<random>, under the prefix
# scripts/reap-stale-ci-stacks.sh reaps (default <checkout dir>-ci-, which in CI
# is <repo>-ci-), and is removed on every exit. IN_IMAGE_UID is the non-root
# uid the command runs as (any non-root uid; the default is below).
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <image> <command...>" >&2
  exit 2
fi
image=$1
shift
# A trusted run runs its stages on the image ID its own fresh build wrote
# (`make -s toolchain-image-id`, Makefile IMAGE_FRESH), never on a tag, which a pull request's run sharing the
# daemon can point at any image. With IMAGE_FRESH=true (ci.yml, on a trusted
# run) anything but a sha256: ID is refused. A developer passes a tag or an ID.
if [ "${IMAGE_FRESH:-false}" = true ] && ! [[ $image =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "IMAGE_FRESH=true: <image> must be the sha256: ID the run built, not $image" >&2
  exit 2
fi
network=${IN_IMAGE_NETWORK:-none}
case $network in
  none | bridge) ;;
  *) echo "IN_IMAGE_NETWORK must be none or bridge: $network" >&2; exit 2 ;;
esac

# Run as the image's user, uid 1000 (builder). The toolchain image's /src is the WORKDIR uid 1000
# creates (build/docker/devcontainer/Dockerfile), mode 755, and the copy-in
# keeps its owner, so only uid 1000 can create Gradle's top-level entries in
# it: .gradle (the project and configuration caches), build/ and .kotlin.
# IN_IMAGE_UID still overrides.
: "${IN_IMAGE_UID:=1000}"
uid=${IN_IMAGE_UID:-10001}
case $uid in
  "" | 0 | *[!0-9]*) echo "IN_IMAGE_UID must be a non-root numeric uid: $uid" >&2; exit 2 ;;
esac
prefix=${CI_STACK_PREFIX:-$(basename "$PWD")-ci-}
name="${prefix}tc-$$-${RANDOM}"
cache=${CI_CACHE:-on}
case $cache in
  on | off) ;;
  *) echo "CI_CACHE must be on or off: $cache" >&2; exit 2 ;;
esac
class=${CI_CACHE_CLASS:-pr}
case $class in
  pr | main) ;;
  *) echo "CI_CACHE_CLASS must be pr or main: $class" >&2; exit 2 ;;
esac
cpus=${IN_IMAGE_CPUS:-}
if [ -z "$cpus" ]; then
  quota=max period=100000
  if [ -r /sys/fs/cgroup/cpu.max ]; then read -r quota period < /sys/fs/cgroup/cpu.max; fi
  case $quota in
    max | "" | *[!0-9]*) cpus=$(nproc) ;;
    *) cpus=$(((quota + period - 1) / period)) ;;
  esac
fi
case $cpus in
  "" | 0 | *[!0-9]*) echo "IN_IMAGE_CPUS must be a positive integer: $cpus" >&2; exit 2 ;;
esac
# The daemon refuses --cpus above its own CPU count, and the job container can
# see more CPUs than the daemon that runs the stage (a pooled runner host), so
# the bound is capped at the daemon's NCPU when the daemon reports one.
daemon_cpus=$(docker info --format '{{.NCPU}}' 2>/dev/null || true)
case $daemon_cpus in
  "" | 0 | *[!0-9]*) ;;
  *) if [ "$cpus" -gt "$daemon_cpus" ]; then cpus=$daemon_cpus; fi ;;
esac
args=(
  --name "$name"
  --cpus "$cpus"
  --env GOMAXPROCS="$cpus"
  --env GOFLAGS="-p=$cpus"
  --init
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --pids-limit 4096
  --ulimit memlock=67108864:67108864
  --ulimit core=1048576:1048576
  --ulimit nofile=65536:65536
  --tmpfs "/tmp:rw,exec,nosuid,nodev,size=3g,mode=1777"
  --network "$network"
  --user "$uid:$uid"
  --workdir /src
  --env HOME=/tmp
  --env CI="${CI:-}"
)
modcache=/tmp/gomodcache
if [ "$cache" = on ]; then
  vols="${prefix}cache-${class}"
  docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges:true --user 0:0 \
    -v "$vols-gobuild:/c/gobuild" -v "$vols-golangci:/c/golangci" -v "$vols-gomod:/c/gomod" \
    "$image" sh -c "for d in /c/*; do [ \"\$(stat -c %u:%g \"\$d\")\" = $uid:$uid ] || chown $uid:$uid \"\$d\"; done" >/dev/null
  args+=(
    -v "$vols-gobuild:/cache/gobuild" --env GOCACHE=/cache/gobuild
    -v "$vols-golangci:/cache/golangci" --env GOLANGCI_LINT_CACHE=/cache/golangci
  )
  if [ "$network" = bridge ]; then
    args+=(-v "$vols-gomod:/cache/gomod")
    modcache=/cache/gomod
  fi
fi
if [ "$network" = bridge ]; then
  # The baked module cache is read-only to the run's user and holds only the
  # root module's build list; the nested modules deps-check walks fetch more.
  # They come from the proxy only: the list ends without `direct`, so a module
  # the proxy cannot serve fails the stage instead of being fetched from its
  # origin repository.
  args+=(--env "GOPROXY=https://proxy.golang.org" --env "GOMODCACHE=$modcache")
  # ci-template v1.36: the Trivy database repositories the runner sets (the
  # dev-cache ghcr mirror on the LAN first, the public ones after) travel
  # with the stage, so `make security` and `trivy image` fetch the vulnerability
  # and Java databases from the LAN instead of the internet.
  for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
    TRIVY_DB_REPOSITORY TRIVY_JAVA_DB_REPOSITORY TRIVY_INSECURE; do
    if [ -n "${!v:-}" ]; then args+=(--env "$v"); fi
  done
fi
# Gradle and the Android tools. A fresh, writable
# GRADLE_USER_HOME per stage on an anonymous volume (removed with the container,
# docker rm -v); dependencies come from the image's GRADLE_RO_DEP_CACHE. user.home
# and ANDROID_USER_HOME go to /tmp: an IN_IMAGE_UID other than 1000 has no passwd
# entry (compose.yaml).
args+=(
  --volume /gradle-home --env GRADLE_USER_HOME=/gradle-home
  --env ANDROID_USER_HOME=/tmp/.android
  --env JAVA_TOOL_OPTIONS=-Duser.home=/tmp
)

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker create "${args[@]}" "$image" sh -c "$*" >/dev/null
tar -C "$PWD" --owner="$uid" --group="$uid" --numeric-owner -cf - . |
  docker cp -a - "$name:/src"
docker start -a "$name"
